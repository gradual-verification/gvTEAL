package viper.silicon.state

import viper.silicon.supporters.{NodeHash, NodeEquiv}
import viper.silicon.state.terms.Term
import viper.silver.ast
import scala.collection.concurrent.TrieMap

object reconstructedPermissions {

  val nodeHash = new NodeHash[ast.MethodCall]
  val nodeEquiv = new NodeEquiv[ast.MethodCall]

  // TODO: We can likely remove the Term entry here, making this a 2-tuple
  case class PermInfo(permissions: Iterable[ast.Exp], branchInfo: Seq[(Term, ast.Node, Option[CheckPosition])])

  private val permissionsMap = new TrieMap[ast.MethodCall, Seq[PermInfo]](nodeHash, nodeEquiv)

  def addMethodCallStatement(call: ast.MethodCall, permissions: Iterable[ast.Exp],
    branch: Seq[(Term, ast.Node, Option[CheckPosition])]) = {

    permissionsMap.get(call) match {
      case None => permissionsMap += (call -> Seq(PermInfo(permissions, branch)))
      case Some(permInfoSequence) =>
        permissionsMap += (call -> (PermInfo(permissions, branch) +: permInfoSequence))
    }
  }

  def getPermissionsFor(call: ast.MethodCall): Seq[PermInfo] = {
    permissionsMap(call)
  }

  def getPermissions = permissionsMap
}
