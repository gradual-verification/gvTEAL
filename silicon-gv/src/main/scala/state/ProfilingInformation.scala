package viper.silicon.state

import java.util.concurrent.atomic.AtomicInteger

// WARNING: this must be changed to be local to individual methods! ie, this is
// currently (probably) not thread safe in that way

object profilingInfo {

  private val eliminatedConjuncts = new AtomicInteger(0);

  private val totalConjuncts = new AtomicInteger(0);

  def incrementEliminatedConjuncts = eliminatedConjuncts.incrementAndGet()

  def incrementEliminatedConjuncts(value: Int): Int = {
    eliminatedConjuncts.addAndGet(value)
  }

  def incrementTotalConjuncts = totalConjuncts.incrementAndGet()

  def incrementTotalConjuncts(value: Int): Int = {
    totalConjuncts.addAndGet(value)
  }

  def getEliminatedConjuncts = eliminatedConjuncts.get()

  def getTotalConjuncts = totalConjuncts.get()

  def reset = {
    eliminatedConjuncts.set(0)
    totalConjuncts.set(0)
  }
}
