// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include "queueing.h"
#include <linux/skb_array.h>

struct multicore_worker __percpu *
wg_packet_percpu_multicore_worker_alloc(work_func_t function, void *ptr)
{
	int cpu;
	struct multicore_worker __percpu *worker = alloc_percpu(struct multicore_worker);

	if (!worker)
		return NULL;

	for_each_possible_cpu(cpu) {
		per_cpu_ptr(worker, cpu)->ptr = ptr;
		INIT_WORK(&per_cpu_ptr(worker, cpu)->work, function);
	}
	return worker;
}

int wg_packet_queue_init(struct crypt_queue *queue, work_func_t function,
			 unsigned int len)
{
	int ret;

	memset(queue, 0, sizeof(*queue));
	queue->last_cpu = -1;
	ret = ptr_ring_init(&queue->ring, len, GFP_KERNEL);
	if (ret)
		return ret;
	queue->worker = wg_packet_percpu_multicore_worker_alloc(function, queue);
	if (!queue->worker) {
		ptr_ring_cleanup(&queue->ring, NULL);
		return -ENOMEM;
	}
	return 0;
}

void wg_packet_queue_free(struct crypt_queue *queue, bool purge)
{
	free_percpu(queue->worker);
	WARN_ON(!purge && !__ptr_ring_empty(&queue->ring));
	ptr_ring_cleanup(&queue->ring, purge ? __skb_array_destroy_skb : NULL);
}

#define NEXT(skb) ((skb)->prev)
#define STUB(queue) ((struct sk_buff *)&queue->empty)

void wg_prev_queue_init(struct prev_queue *queue)
{
	NEXT(STUB(queue)) = NULL;
	queue->head = queue->tail = STUB(queue);
	queue->peeked = NULL;
	atomic_set(&queue->count, 0);
	BUILD_BUG_ON(
		offsetof(struct sk_buff, next) != offsetof(struct prev_queue, empty.next) -
							offsetof(struct prev_queue, empty) ||
		offsetof(struct sk_buff, prev) != offsetof(struct prev_queue, empty.prev) -
							 offsetof(struct prev_queue, empty));
}

static void __wg_prev_queue_enqueue(struct prev_queue *queue, struct sk_buff *skb)
{
	WRITE_ONCE(NEXT(skb), NULL);
	WRITE_ONCE(NEXT(xchg_release(&queue->head, skb)), skb);
}

bool wg_prev_queue_enqueue(struct prev_queue *queue, struct sk_buff *skb)
{
	if (!atomic_add_unless(&queue->count, 1, MAX_QUEUED_PACKETS))
		return false;
	__wg_prev_queue_enqueue(queue, skb);
	return true;
}

struct sk_buff *wg_prev_queue_dequeue(struct prev_queue *queue)
{
	struct sk_buff *tail = queue->tail, *next = smp_load_acquire(&NEXT(tail));

	if (tail == STUB(queue)) {
		if (!next)
			return NULL;
		queue->tail = next;
		tail = next;
		next = smp_load_acquire(&NEXT(next));
	}
	if (next) {
		queue->tail = next;
		atomic_dec(&queue->count);
		return tail;
	}
	if (tail != READ_ONCE(queue->head))
		return NULL;
	__wg_prev_queue_enqueue(queue, STUB(queue));
	next = smp_load_acquire(&NEXT(tail));
	if (next) {
		queue->tail = next;
		atomic_dec(&queue->count);
		return tail;
	}
	return NULL;
}

bool wg_reorder_queue_enqueue(struct reorder_queue *queue, struct sk_buff *skb)
{
	u64 auth_counter = le64_to_cpu(((struct message_data *)skb->data)->counter);
	if (unlikely(auth_counter == 0)) // Zero auth counter means a new handshake was just completed, keep sequence numbers contiguous
	{
		if (queue->last_enq_seq_num != 0) // First ever packet is a special case, sequence starts with 0
		{
			queue->seq_num_offset = queue->last_enq_seq_num + 1;
		}
	}
	u64 seq_num = auth_counter + queue->seq_num_offset;
	u16 buf_idx = seq_num % REORDER_QUEUE_LEN;

	// Declaring this here solely for debug prints to know the device name and peer address
	struct wg_peer * peer = container_of(queue, struct wg_peer, rx_queue);

	if (unlikely(seq_num < (queue->next_deq_seq_num)))
	{
		net_dbg_ratelimited("%s: Dropping seqnum %llu from peer %llu (%pISpfsc) which missed the reordering window (max reordering delay too low?)\n",
			peer->device->dev->name, seq_num, peer->internal_id, &peer->endpoint.addr);
		return false;
	}

	if (unlikely(queue->ring_buffer[buf_idx].packet != NULL))
	{
		if (queue->ring_buffer[buf_idx].enqueued_at + MAX_REORDER_DLY_USEC > ktime_get()) // Disregard occupant if it's stale
		{
			if (queue->ring_buffer[buf_idx].seq_num == seq_num)
			{
				net_dbg_ratelimited("%s: Dropping duplicate packet with seqnum %llu from peer %llu (%pISpfsc), received before ingesting the first one\n",
					peer->device->dev->name, seq_num, peer->internal_id, &peer->endpoint.addr);
			}
			else
			{
				net_dbg_ratelimited("%s: Dropping seqnum %llu from peer %llu (%pISpfsc) due to occupied buffer slot (reordering buffer too small?)\n",
					peer->device->dev->name, seq_num, peer->internal_id, &peer->endpoint.addr);
			}
			return false;
		}
	}

	if (queue->last_enq_seq_num < seq_num) queue->last_enq_seq_num = seq_num;
	queue->ring_buffer[buf_idx].packet = skb;
	queue->ring_buffer[buf_idx].seq_num = seq_num;
	queue->ring_buffer[buf_idx].enqueued_at = ktime_get();
	return true;
}

static inline struct sk_buff * _wg_reorder_queue_dequeue(struct reorder_queue *queue, u16 buf_idx)
{
	struct sk_buff * ret = queue->ring_buffer[buf_idx].packet;
	queue->next_deq_seq_num = queue->ring_buffer[buf_idx].seq_num + 1;
	queue->ring_buffer[buf_idx].packet = NULL;
	queue->last_deq_time = ktime_get();
	return ret;
}

struct sk_buff *wg_reorder_queue_dequeue(struct reorder_queue *queue)
{
	u16 buf_idx = queue->next_deq_seq_num % REORDER_QUEUE_LEN;
	if (likely(queue->ring_buffer[buf_idx].packet)) {
		return _wg_reorder_queue_dequeue(queue, buf_idx);
	}

	// Don't look for the next packet after a gap until the max reorder delay has passed
	if (likely(queue->last_deq_time + MAX_REORDER_DLY_USEC > ktime_get())) return NULL;

	// If we're past the reordering delay, find the next valid packet in the buffer and pop it
	u64 next_seq_num = queue->next_deq_seq_num + 1;
	u16 next_idx = next_seq_num % REORDER_QUEUE_LEN;
	while (queue->ring_buffer[next_idx].packet == NULL)
	{
		next_seq_num++;
		next_idx = next_seq_num % REORDER_QUEUE_LEN;
		if (next_seq_num > queue ->last_enq_seq_num) return NULL; // There are no more packets in the buffer in this case
	}

	// Declaring this here solely for debug prints to know the device name and peer address
	struct wg_peer * peer = container_of(queue, struct wg_peer, rx_queue);

	net_dbg_ratelimited("%s: Skipping over gap between seqnum %llu and %llu from peer %llu (%pISpfsc)\n",
		peer->device->dev->name, queue->next_deq_seq_num, next_seq_num, peer->internal_id, &peer->endpoint.addr);

	if (unlikely(queue->ring_buffer[next_idx].seq_num != next_seq_num))
	{
		pr_debug("%s: Somehow there's a packet with seqnum %llu in the reordering buffer of peer %llu (%pISpfsc) instead of seqnum %llu. Ingesting it anyway.\n",
			peer->device->dev->name, queue->ring_buffer[next_idx].seq_num, peer->internal_id, &peer->endpoint.addr, next_seq_num);
	}

	return _wg_reorder_queue_dequeue(queue, next_idx);
}

#undef NEXT
#undef STUB
