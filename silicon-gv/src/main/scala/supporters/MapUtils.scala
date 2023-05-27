
package viper.silicon.supporters

import viper.silver.ast.Node

import scala.util.hashing.Hashing

class NodeHash[A] extends Hashing[A] {

  def hash(call: A): Int = {
    call.hashCode()
  }
}

class NodeEquiv[A <: Node] extends Equiv[A] {

  def equiv(checkPosition1: A, checkPosition2: A): Boolean = {
    checkPosition1.uniqueIdentifier == checkPosition2.uniqueIdentifier
  }
}

