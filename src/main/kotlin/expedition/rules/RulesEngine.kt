package expedition.rules

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/**
 * The ordered rule list (thread-safe: edited from the EDT / control API, read from Netty
 * workers). Empty by default, in which case the rules layer only observes traffic and never
 * changes it. Hit counters live here so [HttpRule] stays an immutable value.
 */
class RulesEngine {
    private val rules = CopyOnWriteArrayList<HttpRule>()
    private val hits = ConcurrentHashMap<Long, AtomicInteger>()
    private val ids = AtomicLong(1)

    /** Webhook actions are inert unless the operator turns this on (never persisted). */
    @Volatile var webhooksEnabled: Boolean = false

    /** Invoked after the rule list changes (persistence). Must not throw. */
    @Volatile var onChange: (() -> Unit)? = null
    private fun changed() { runCatching { onChange?.invoke() } }

    fun rules(): List<HttpRule> = rules.toList()
    fun get(id: Long): HttpRule? = rules.firstOrNull { it.id == id }
    fun hitCount(id: Long): Int = hits[id]?.get() ?: 0

    /** Adds [rule] (assigning an id when it has none) at [index] (default: end). Returns the stored rule. */
    @Synchronized
    fun add(rule: HttpRule, index: Int? = null): HttpRule {
        rule.validate()
        val r = if (rule.id <= 0 || rules.any { it.id == rule.id }) rule.copy(id = ids.getAndIncrement()) else rule
        ids.updateAndGet { maxOf(it, r.id + 1) }
        if (index == null || index !in 0..rules.size) rules.add(r) else rules.add(index, r)
        changed()
        return r
    }

    /** Replaces rule [id] (keeping its id and position) and resets its hit counter. */
    @Synchronized
    fun update(id: Long, rule: HttpRule): HttpRule? {
        rule.validate()
        val i = rules.indexOfFirst { it.id == id }
        if (i < 0) return null
        val r = rule.copy(id = id)
        rules[i] = r
        hits.remove(id)
        changed()
        return r
    }

    @Synchronized
    fun remove(id: Long): Boolean = rules.removeIf { it.id == id }.also { if (it) { hits.remove(id); changed() } }

    @Synchronized
    fun clear() { rules.clear(); hits.clear(); changed() }

    @Synchronized
    fun setEnabled(id: Long, enabled: Boolean): Boolean {
        val i = rules.indexOfFirst { it.id == id }
        if (i < 0) return false
        rules[i] = rules[i].copy(enabled = enabled)
        changed()
        return true
    }

    /** Moves rule [id] to position [to] (clamped). */
    @Synchronized
    fun moveTo(id: Long, to: Int): Boolean {
        val i = rules.indexOfFirst { it.id == id }
        if (i < 0) return false
        val r = rules.removeAt(i)
        rules.add(to.coerceIn(0, rules.size), r)
        changed()
        return true
    }

    /** Reorders to exactly [order] (a permutation of the current ids). */
    @Synchronized
    fun reorder(order: List<Long>) {
        val current = rules.associateBy { it.id }
        require(order.size == current.size && order.toSet() == current.keys) { "ids must be a permutation of the current rule ids" }
        val next = order.map { current.getValue(it) }
        rules.clear(); rules.addAll(next)
        changed()
    }

    fun resetHits(id: Long? = null) { if (id == null) hits.clear() else hits.remove(id) }

    fun exhausted(rule: HttpRule): Boolean = rule.times != null && hitCount(rule.id) >= rule.times

    /** True when some enabled, not-exhausted rule exists (otherwise traffic is only observed). */
    fun hasActive(direction: RuleDirection? = null, listener: String? = null): Boolean =
        rules.any {
            it.enabled && !exhausted(it) && (direction == null || it.matcher.direction == direction) &&
                (listener == null || it.matcher.listener == null || it.matcher.listener.equals(listener, ignoreCase = true))
        }

    /**
     * True when an enabled, not-exhausted REQUEST rule scoped to [listener] (or unscoped) can answer
     * locally (mock or redirect) — such a connection may never need its own upstream.
     */
    fun hasActiveLocalAnswer(listener: String): Boolean =
        rules.any {
            it.enabled && !exhausted(it) && it.matcher.direction == RuleDirection.REQUEST &&
                (it.matcher.listener == null || it.matcher.listener.equals(listener, ignoreCase = true)) &&
                it.actions.any { a -> a is RuleAction.MockResponse || a is RuleAction.Redirect }
        }

    /** Atomically claims one use of [rule]; false once its [HttpRule.times] budget is spent. */
    internal fun tryConsume(rule: HttpRule): Boolean {
        val c = hits.computeIfAbsent(rule.id) { AtomicInteger() }
        val limit = rule.times ?: run { c.incrementAndGet(); return true }
        while (true) {
            val v = c.get()
            if (v >= limit) return false
            if (c.compareAndSet(v, v + 1)) return true
        }
    }
}
