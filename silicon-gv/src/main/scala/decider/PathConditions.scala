// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2011-2019 ETH Zurich.

package viper.silicon.decider

import viper.silver.ast.Exp
import viper.silicon.common.collections.immutable.InsertionOrderedSet
import viper.silicon.Stack
import viper.silicon.state.CheckPosition
import viper.silicon.state.terms.{And, Decl, Equals, Implies, Quantification, Quantifier, Term, Trigger, True, Var, sorts}
import viper.silicon.utils
import viper.silicon.utils.Counter

/*
 * Interfaces
 */

/* TODO: 'contains' functionality currently not needed. If removed, 'allAssumptions' could
 *       probably removed as well.
 *       Benchmark runtime difference!
 */

trait RecordedPathConditions {
  def branchConditions: Stack[Term]
  def branchConditionsSemanticAstNodes: Stack[Exp]
  def branchConditionsAstNodes: Stack[Exp]
  def branchConditionsOrigins: Stack[Option[CheckPosition]]

  def assumptions: InsertionOrderedSet[Term]
  def declarations: InsertionOrderedSet[Decl]

  def contains(assumption: Term): Boolean

  def conditionalized: Seq[Term]

  def quantified(quantifier: Quantifier,
                 qvars: Seq[Var],
                 triggers: Seq[Trigger],
                 name: String,
                 isGlobal: Boolean,
                 ignore: Term /* TODO: Hack, implement properly */)
                : (Seq[Quantification], Seq[Quantification])

  // If the heap does not contain a mapping for a snapshot(?) value, the path
  // condition must...? maybe
  def getEquivalentVariables(variable: Term, lenient: Boolean = false): Seq[Term] = {
    assumptions.foldRight[Seq[Term]](Seq.empty)((term, equivalentVars) => term match {
      case Equals(var1 @ Var(_, _), term2) if term2 == variable =>
        var1 +: equivalentVars
      case Equals(term1, var2 @ Var(_, _)) if term1 == variable =>
        var2 +: equivalentVars
      case Equals(var1 @ Var(_, _), term2) if lenient && term2.toString == variable.toString && term2.sort == variable.sort =>
        var1 +: equivalentVars
      case Equals(term1, var2 @ Var(_, _)) if lenient && term1.toString == variable.toString && term1.sort == variable.sort =>
        var2 +: equivalentVars
      case Equals(term1, term2) if lenient && term1.sort == sorts.Ref && term2.toString == variable.toString && term2.sort == variable.sort =>
        term1 +: equivalentVars
      case Equals(term1, term2) if lenient && term2.sort == sorts.Ref && term1.toString == variable.toString && term1.sort == variable.sort =>
        term2 +: equivalentVars
      case _ => equivalentVars
    })
  }
}

trait PathConditionStack extends RecordedPathConditions {
  def setCurrentBranchCondition(condition: Term,
    conditionSemanticAstNode: Exp,
    conditionAstNode: Exp,
    conditionOrigin: Option[CheckPosition]): Unit
  def add(assumption: Term): Unit
  def add(declaration: Decl): Unit
  def pushScope(): Unit
  def popScope(): Unit
  def mark(): Mark
  def after(mark: Mark): RecordedPathConditions
  def isEmpty: Boolean
  def duplicate(): PathConditionStack
    /* Public method 'clone' impossible, see https://issues.scala-lang.org/browse/SI-6760 */
}

/*
 * Implementations (mostly mutable!)
 */

private class PathConditionStackLayer
    extends Mutable
       with Cloneable {

  private var _branchCondition: Option[Term] = None
  private var _branchConditionSemanticAstNode: Option[Exp] = None
  private var _branchConditionAstNode: Option[Exp] = None
  private var _branchConditionOrigin: Option[Option[CheckPosition]] = None
  private var _globalAssumptions: InsertionOrderedSet[Quantification] = InsertionOrderedSet.empty
  private var _nonGlobalAssumptions: InsertionOrderedSet[Term] = InsertionOrderedSet.empty
  private var _declarations: InsertionOrderedSet[Decl] = InsertionOrderedSet.empty

  def branchCondition: Option[Term] = _branchCondition
  def branchConditionSemanticAstNode: Option[Exp] = _branchConditionSemanticAstNode
  def branchConditionAstNode: Option[Exp] = _branchConditionAstNode
  def branchConditionOrigin: Option[Option[CheckPosition]] = _branchConditionOrigin
  def globalAssumptions: InsertionOrderedSet[Quantification] = _globalAssumptions
  def nonGlobalAssumptions: InsertionOrderedSet[Term] = _nonGlobalAssumptions
  def declarations: InsertionOrderedSet[Decl] = _declarations

  def assumptions: InsertionOrderedSet[Term] = globalAssumptions ++ nonGlobalAssumptions
  def pathConditions: InsertionOrderedSet[Term] = assumptions ++ branchCondition

  def branchCondition_=(condition: Term) {
    assert(_branchCondition.isEmpty,
        s"Branch condition is already set (to ${_branchCondition.get}), "
      + s"won't override (with $condition).")

    _branchCondition = Some(condition)
  }

  def branchConditionSemanticAstNode_=(conditionSemanticAstNode: Exp) {

    assert(_branchConditionSemanticAstNode.isEmpty,
      s"Branch condition position is already set (to ${_branchConditionSemanticAstNode.get}), "
    + s"refusing to override (with $conditionSemanticAstNode).")

    _branchConditionSemanticAstNode = Some(conditionSemanticAstNode)
  }

  def branchConditionAstNode_=(conditionAstNode: Exp) {

    assert(_branchConditionAstNode.isEmpty,
        s"Branch condition position is already set (to ${_branchConditionAstNode.get}), "
      + s"refusing to override (with $conditionAstNode).")

    _branchConditionAstNode = Some(conditionAstNode)
  }

  def branchConditionOrigin_=(conditionOrigin: Option[CheckPosition]) {

    assert(_branchConditionOrigin.isEmpty,
      s"Branch condition origin is already set (to ${_branchConditionOrigin.get}), "
    + s"refusing to override (with $conditionOrigin).")

    _branchConditionOrigin = Some(conditionOrigin)
  }

  def add(assumption: Term): Unit = {
    assert(
      !assumption.isInstanceOf[And],
      s"Unexpectedly found a conjunction (should have been split): $assumption")

    /* TODO: Don't record branch conditions as assumptions */

    assumption match {
      case quantification: Quantification if quantification.isGlobal =>
        _globalAssumptions += quantification
      case _ =>
        _nonGlobalAssumptions += assumption
    }
  }

  def add(declaration: Decl): Unit = _declarations += declaration

  def contains(pathCondition: Term): Boolean = {
    assert(
      !pathCondition.isInstanceOf[And],
      s"Unexpectedly found a conjunction (should have been split): $pathCondition")

    pathCondition match {
      case quantification: Quantification if quantification.isGlobal =>
        /* Assumption: globals are never used as branch conditions */
        _globalAssumptions.contains(quantification)
      case _ =>
        _nonGlobalAssumptions.contains(pathCondition) || _branchCondition.contains(pathCondition)
    }
  }

  override def clone(): AnyRef = {
    /* Attention: the original and its clone must not share any mutable data! */
    super.clone()
  }
}

private trait LayeredPathConditionStackLike {
  protected def branchConditions(layers: Stack[PathConditionStackLayer]): Stack[Term] =
    layers.flatMap(_.branchCondition)

  protected def branchConditionsSemanticAstNodes(layers:
    Stack[PathConditionStackLayer]): Stack[Exp] =
      layers.flatMap(_.branchConditionSemanticAstNode)

  protected def branchConditionsAstNodes(layers: Stack[PathConditionStackLayer]): Stack[Exp] =
    layers.flatMap(_.branchConditionAstNode)

  protected def branchConditionsOrigins(layers: Stack[PathConditionStackLayer]): Stack[Option[CheckPosition]] =
    layers.flatMap(_.branchConditionOrigin)

  protected def assumptions(layers: Stack[PathConditionStackLayer]): InsertionOrderedSet[Term] =
    InsertionOrderedSet(layers.flatMap(_.assumptions)) // Note: Performance?

  protected def declarations(layers: Stack[PathConditionStackLayer]): InsertionOrderedSet[Decl] =
    InsertionOrderedSet(layers.flatMap(_.declarations)) // Note: Performance?

  protected def contains(layers: Stack[PathConditionStackLayer], assumption: Term): Boolean =
    layers exists (_.contains(assumption))

  protected def conditionalized(layers: Stack[PathConditionStackLayer]): Seq[Term] = {
    var unconditionalTerms = Vector.empty[Term]
    var conditionalTerms = Vector.empty[Term]

    for (layer <- layers) {
      unconditionalTerms ++= layer.globalAssumptions

      conditionalTerms :+=
        Implies(layer.branchCondition.getOrElse(True()), And(layer.nonGlobalAssumptions))
    }

    unconditionalTerms ++ conditionalTerms
  }

  protected def quantified(layers: Stack[PathConditionStackLayer],
                           quantifier: Quantifier,
                           qvars: Seq[Var],
                           triggers: Seq[Trigger],
                           name: String,
                           isGlobal: Boolean,
                           ignore: Term)
                          : (Seq[Quantification], Seq[Quantification]) = {

    var globals = Vector.empty[Quantification]
    var nonGlobals = Vector.empty[Quantification]

    val ignores = ignore.topLevelConjuncts

    for (layer <- layers) {
      globals ++= layer.globalAssumptions

      nonGlobals :+=
        Quantification(
          quantifier,
          qvars,
          And(layer.nonGlobalAssumptions -- ignores),
          triggers,
          name,
          isGlobal)
    }

    (globals, nonGlobals)
  }
}

private class DefaultRecordedPathConditions(from: Stack[PathConditionStackLayer])
    extends LayeredPathConditionStackLike
       with RecordedPathConditions
       with Immutable {

  val branchConditions: Stack[Term] = branchConditions(from)
  val branchConditionsSemanticAstNodes: Stack[Exp] = branchConditionsSemanticAstNodes(from)
  val branchConditionsAstNodes: Stack[Exp] = branchConditionsAstNodes(from)
  val branchConditionsOrigins: Stack[Option[CheckPosition]] = branchConditionsOrigins(from)
  val assumptions: InsertionOrderedSet[Term] = assumptions(from)
  val declarations: InsertionOrderedSet[Decl] = declarations(from)

  def contains(assumption: Term): Boolean = contains(from, assumption)

  val conditionalized: Seq[Term] = conditionalized(from)

  def quantified(quantifier: Quantifier,
                 qvars: Seq[Var],
                 triggers: Seq[Trigger],
                 name: String,
                 isGlobal: Boolean,
                 ignore: Term)
                : (Seq[Quantification], Seq[Quantification]) = {

    quantified(from, quantifier, qvars, triggers, name, isGlobal, ignore)
  }
}

private[decider] class LayeredPathConditionStack
    extends LayeredPathConditionStackLike
       with PathConditionStack
       with Mutable
       with Cloneable {

  private var layers: Stack[PathConditionStackLayer] = Stack.empty
  private var markToLength: Map[Mark, Int] = Map.empty
  private var scopeMarks: List[Mark] = List.empty
  private var markCounter = new Counter(0)

  /* Set of assumptions across all layers. Maintained separately to improve performance. */
  private var allAssumptions = InsertionOrderedSet.empty[Term]

  pushScope() /* Create an initial layer on the stack */

  def setCurrentBranchCondition(condition: Term,
    conditionSemanticAstNode: Exp,
    conditionAstNode: Exp,
    conditionOrigin: Option[CheckPosition]): Unit = {
    /* TODO: Split condition into top-level conjuncts as well? */

    layers.head.branchCondition = condition
    layers.head.branchConditionSemanticAstNode = conditionSemanticAstNode
    layers.head.branchConditionAstNode = conditionAstNode
    layers.head.branchConditionOrigin = conditionOrigin
  }

  def add(assumption: Term): Unit = {
    /* TODO: Would be cleaner to not add assumptions that are already set as branch conditions */

    val tlcs = assumption.topLevelConjuncts

    tlcs foreach layers.head.add
    allAssumptions ++= tlcs
  }

  def add(declaration: Decl): Unit = {
    layers.head.add(declaration)
  }

  def pushScope(): Unit = {
    val scopeMark = pushLayer()
    scopeMarks = scopeMark :: scopeMarks
  }

  def popScope(): Unit = {
    val scopeMark = scopeMarks.head
    scopeMarks = scopeMarks.tail

    popLayersAndRemoveMark(scopeMark)
  }

  private def pushLayer(): Mark = {
    val mark = markCounter.next()

    markToLength += (mark -> layers.length)
    layers = new PathConditionStackLayer() +: layers

    mark
  }

  private def popLayersAndRemoveMark(mark: Mark): Unit = {
    val targetLength = markToLength(mark)
    val dropLength = layers.length - targetLength

    markToLength = markToLength - mark

//    /* Remove marks pointing to popped layers (including mark itself) */
//    markToLength = markToLength filter (_._2 < targetLength)
//      /* TODO: Performance? Do lazily, e.g. when isEmpty is called? */

    var i = 0
    layers =
      layers.dropWhile(layer => {
        i += 1
        allAssumptions --= layer.assumptions
        i < dropLength
        /* If i < dropLength is false, the current - and last-to-drop - layer won't be
         * dropped, but its assumptions have already been removed from allAssumptions.
         * Subsequently taking the tail of the remaining layers results in also
         * dropping the last layer that needs to be dropped.
         */
      }).tail
  }

  def branchConditions: Stack[Term] = layers.flatMap(_.branchCondition)

  def branchConditionsSemanticAstNodes: Stack[Exp] = layers.flatMap(_.branchConditionSemanticAstNode)

  def branchConditionsAstNodes: Stack[Exp] = layers.flatMap(_.branchConditionAstNode)

  def branchConditionsOrigins: Stack[Option[CheckPosition]] = layers.flatMap(_.branchConditionOrigin)

  def assumptions: InsertionOrderedSet[Term] = allAssumptions

  def declarations: InsertionOrderedSet[Decl] =
    InsertionOrderedSet(layers.flatMap(_.declarations)) // Note: Performance?

  def contains(assumption: Term): Boolean = allAssumptions.contains(assumption)

  def conditionalized: Seq[Term] = conditionalized(layers)

  def quantified(quantifier: Quantifier,
                 qvars: Seq[Var],
                 triggers: Seq[Trigger],
                 name: String,
                 isGlobal: Boolean,
                 ignore: Term)
                : (Seq[Quantification], Seq[Quantification]) = {

    quantified(layers, quantifier, qvars, triggers, name, isGlobal, ignore)
  }

  def mark(): Mark = pushLayer()

  def after(mark: Mark): RecordedPathConditions = {
    val afterLength = layers.length - markToLength(mark)
    val afterLayers = layers.take(afterLength)

    new DefaultRecordedPathConditions(afterLayers)
  }

  def isEmpty: Boolean = (
       layers.forall(_.branchCondition.isEmpty)
    && allAssumptions.isEmpty
    && (markToLength.keySet -- scopeMarks).isEmpty)

  override def duplicate(): LayeredPathConditionStack = {
    /* Attention: The original and its clone must not share any mutable data! */

    val clonedStack = new LayeredPathConditionStack

    /* Sharing immutable data is safe */
    clonedStack.allAssumptions = allAssumptions
    clonedStack.markToLength = markToLength
    clonedStack.scopeMarks = scopeMarks

    /* Mutable data is cloned */
    clonedStack.markCounter = markCounter.clone()
    clonedStack.layers = layers map (_.clone().asInstanceOf[PathConditionStackLayer])

    clonedStack
  }

  override def toString: String =  {
    val sb = new StringBuilder(s"${this.getClass.getSimpleName}:\n")
    val sep = s" ${"-" * 10}\n"

    sb.append(sep)

    sb.append(s"  height: ${layers.length}\n")
    sb.append(s"  allAssumptions:\n")
    for (assumption <- allAssumptions) {
      sb.append(s"    $assumption\n")
    }

    sb.append(sep)

    for (layer <- layers) {
      sb.append(s"  branch condition: ${layer.branchCondition}\n")
      sb.append( "  assumptions:\n")
      for (assumption <- layer.assumptions) {
        sb.append(s"    $assumption\n")
      }
    }

    sb.append(sep)

    val marks = markToLength.keySet -- scopeMarks
    sb.append("  marks:\n")
    marks foreach (m => {
      sb.append(s"    $m -> ${markToLength(m)} (${scopeMarks.contains(m)})\n")
    })

    sb.result()
  }
}
