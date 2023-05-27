package viper.silicon.state

import viper.silver.ast

sealed trait LoopPosition

object LoopPosition {
  case object Before extends LoopPosition
  case object After extends LoopPosition
  case object Beginning extends LoopPosition
  case object End extends LoopPosition
}

sealed trait CheckPosition {

  def canEqual(a: Any) = a.isInstanceOf[CheckPosition]

  override def equals(that: Any): Boolean = that match {
    // test that `that` is an instance of CheckPosition
    case that: CheckPosition => {
      // test that `this` is an instance of `that`
      that.canEqual(this) &&
      ((this, that) match {
        case (CheckPosition.GenericNode(node1), CheckPosition.GenericNode(node2)) => node1.uniqueIdentifier == node2.uniqueIdentifier
        case (CheckPosition.Loop(nodes1, position1), CheckPosition.Loop(nodes2, position2)) =>
          position1 == position2 &&
          nodes1.zip(nodes2).foldRight(true)((nodeTuple: (ast.Node, ast.Node), result: Boolean) => 
            result match {
              case false => false
              case true =>
                nodeTuple match {
                  case (node1, node2) => node1.uniqueIdentifier == node2.uniqueIdentifier
                }
            }
          )
        case _ => false
      })
    }
    case _ => false
  }

  // do we need this?
  //
  // yes, whenever two objects are equal, their hashcodes should be equivalent
  // (this only needs to be true one way, though, ie, equality should imply
  // that the hashcodes are equal)
  //
  // we don't really need to multiply by 7919 (a prime number) here, but it
  // improves hash table performance if unequal objects have distinct hashcodes
  override def hashCode: Int = 7919 * (this match {
    case CheckPosition.GenericNode(node) => node.uniqueIdentifier
    case CheckPosition.Loop(invariants, position) =>
      (invariants.foldRight(0)((silverExpr, result) => {
        // println(s"${result}")
        silverExpr.uniqueIdentifier + result
      })) + (position match {
        case LoopPosition.Before => 31
        case LoopPosition.After => 47
        case LoopPosition.Beginning => 89
        case LoopPosition.End => 101
      })
  })
}

object CheckPosition {
  case class GenericNode(node: ast.Node) extends CheckPosition
  case class Loop(invariants: Seq[ast.Exp], position: LoopPosition) extends CheckPosition
}
