package viper.silicon.state

import viper.silicon.Stack
import viper.silver.ast
import scala.collection.concurrent.{Map, TrieMap}

case class BranchCond(cond: ast.Exp,
                      position: ast.Exp,
                      origin: Option[CheckPosition])
case class CheckInfo(checks: ast.Exp,
  branchInfo: Stack[BranchCond],
  context: ast.Exp,
  forFraming: Boolean)

object runtimeChecks {

  // Maps an ast node to the runtime checks that must be done prior to it.
  //
  // We may need to track branch information for the case where a program
  // statement or expression after a conditional is dependent on the result of
  // the conditional; we may need to check the branch taken in the runtime
  // checks
  //
  // a CheckList is a Seq[CheckInfo]
  
  private var checks: Map[CheckPosition, CheckList] = new TrieMap[CheckPosition, CheckList]

  def addChecks(programPoint: CheckPosition,
    newCheck: ast.Exp,
    branchInfo: Stack[BranchCond],
    context: ast.Exp,
    forFraming: Boolean): Unit = {
    
    checks.get(programPoint) match {
      case None => (checks += (programPoint ->
        List(CheckInfo(newCheck,
          branchInfo,
          context,
          forFraming))))
      case Some(checkList) =>
        (checks += (programPoint ->
          (CheckInfo(newCheck,
            branchInfo,
            context,
            forFraming)
          +: checkList)))
    }
  }

  def getChecks: Map[CheckPosition, CheckList] = {
    checks
  }

  // TODO: This is not thread safe! This may not be safely used to clear the
  // map between parallel test runs
  def reset = {
    checks = new TrieMap[CheckPosition, CheckList]
  }
}
