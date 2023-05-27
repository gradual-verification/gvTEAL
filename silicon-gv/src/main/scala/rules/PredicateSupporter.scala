// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2011-2019 ETH Zurich.

package viper.silicon.rules

import viper.silver.ast
import viper.silver.verifier.PartialVerificationError
import viper.silver.verifier.reasons.InsufficientPermission
import viper.silicon.common.collections.immutable.InsertionOrderedSet
import viper.silicon.interfaces.VerificationResult
import viper.silicon.resources.PredicateID
import viper.silicon.state._
import viper.silicon.state.terms._
import viper.silicon.supporters.Translator
import viper.silicon.utils
import viper.silicon.utils.toSf
import viper.silicon.verifier.Verifier

trait PredicateSupportRules extends SymbolicExecutionRules {
  def fold(s: State,
           predicate: ast.Predicate,
           origin: Option[ast.Fold],
           tArgs: List[Term],
           tPerm: Term,
           constrainableWildcards: InsertionOrderedSet[Var],
           pve: PartialVerificationError,
           v: Verifier)
          (Q: (State, Verifier) => VerificationResult)
          : VerificationResult

  def unfold(s: State,
             predicate: ast.Predicate,
             origin: Option[ast.Unfold],
             tArgs: List[Term],
             tPerm: Term,
             constrainableWildcards: InsertionOrderedSet[Var],
             pve: PartialVerificationError,
             v: Verifier,
             pa: ast.PredicateAccess /* TODO: Make optional */)
            (Q: (State, Verifier) => VerificationResult)
            : VerificationResult
}

object predicateSupporter extends PredicateSupportRules with Immutable {
  import consumer._
  import producer._

  def fold(s: State,
           predicate: ast.Predicate,
           origin: Option[ast.Fold],
           tArgs: List[Term],
           tPerm: Term,
           constrainableWildcards: InsertionOrderedSet[Var],
           pve: PartialVerificationError,
           v: Verifier)
          (Q: (State, Verifier) => VerificationResult)
          : VerificationResult = {

    val body = predicate.body.get /* Only non-abstract predicates can be unfolded */
    val gIns = s.g + Store(predicate.formalArgs map (_.localVar) zip tArgs)
    //println(s"Setting fold AST node in state: ${origin}")
    val s1 = s.copy(g = gIns,
                    oldStore = Some(s.g),
                    oldHeaps = s.oldHeaps + (Verifier.PRE_HEAP_LABEL -> Heap()) + (Verifier.PRE_OPTHEAP_LABEL -> Heap()),
                    smDomainNeeded = true,
                    foldOrUnfoldAstNode = origin)
              .scalePermissionFactor(tPerm)
    consume(s1, body, pve, v)((s1a, snap, v1) => {
      val predTrigger = App(Verifier.predicateData(predicate).triggerFunction,
                            snap.convert(terms.sorts.Snap) +: tArgs)
      v1.decider.assume(predTrigger)
      val s2 = s1a.setConstrainable(constrainableWildcards, false)
      if (s2.qpPredicates.contains(predicate)) {
        val predSnap = snap.convert(s2.predicateSnapMap(predicate))
        val formalArgs = s2.predicateFormalVarMap(predicate)
        val (sm, smValueDef) =
          quantifiedChunkSupporter.singletonSnapshotMap(s2, predicate, tArgs, predSnap, v1)
        v1.decider.prover.comment("Definitional axioms for singleton-SM's value")
        v1.decider.assume(smValueDef)
        val ch =
          quantifiedChunkSupporter.createSingletonQuantifiedChunk(
            formalArgs, predicate, tArgs, tPerm, sm)
        val h3 = s2.h + ch
        val smDef = SnapshotMapDefinition(predicate, sm, Seq(smValueDef), Seq())
        val smCache = {
          val (relevantChunks, _) =
            quantifiedChunkSupporter.splitHeap[QuantifiedPredicateChunk](h3, BasicChunkIdentifier(predicate.name))
          val (smDef1, smCache1) =
            quantifiedChunkSupporter.summarisingSnapshotMap(
              s2, predicate, s2.predicateFormalVarMap(predicate), relevantChunks, v1)
          v1.decider.assume(PredicateTrigger(predicate.name, smDef1.sm, tArgs))

          smCache1
        }

        //println(s"Unsetting fold AST node in state: ${s2.foldOrUnfoldAstNode}")

        val s3 = s2.copy(g = s.g,
                         oldStore = None,
                         oldHeaps = s.oldHeaps,
                         h = h3,
                         smCache = smCache,
                         functionRecorder = s2.functionRecorder.recordFvfAndDomain(smDef),
                         foldOrUnfoldAstNode = None)
        Q(s3, v1)
      } else {
        val ch = BasicChunk(PredicateID, BasicChunkIdentifier(predicate.name), tArgs, snap.convert(sorts.Snap), tPerm)
        val s3 = s2.copy(g = s.g,
                         oldStore = None,
                         oldHeaps = s.oldHeaps,
                         smDomainNeeded = s.smDomainNeeded,
                         permissionScalingFactor = s.permissionScalingFactor)
        chunkSupporter.produce(s3, s3.h, ch, v1)((s4, h1, v2) => {

          //println(s"Unsetting fold AST node in state: ${s4.foldOrUnfoldAstNode}")

          Q(s4.copy(h = h1, foldOrUnfoldAstNode = None), v2)
        })
      }
    })
  }

  // same as consume case for predicates; add profiling here!
  def unfold(s: State,
             predicate: ast.Predicate,
             origin: Option[ast.Unfold],
             tArgs: List[Term],
             tPerm: Term,
             constrainableWildcards: InsertionOrderedSet[Var],
             pve: PartialVerificationError,
             v: Verifier,
             pa: ast.PredicateAccess)
            (Q: (State, Verifier) => VerificationResult)
            : VerificationResult = {

    val gIns = s.g + Store(predicate.formalArgs map (_.localVar) zip tArgs)
    val body = predicate.body.get /* Only non-abstract predicates can be unfolded */
    val s1 = s.scalePermissionFactor(tPerm)
    // This case will never happen; we don't support quantifiers!
    if (s1.qpPredicates.contains(predicate)) {
      val formalVars = s1.predicateFormalVarMap(predicate)
      quantifiedChunkSupporter.consumeSingleLocation(
        s1,
        s1.h,
        formalVars,
        tArgs,
        pa,
        tPerm,
        None,
        pve,
        v
      )((s2, h2, snap, v1) => {
        // TODO: ASK JENNA: we may not need to track the origin of any possible branches here; it looks like
        // this is for quantification? maybe
        val s3 = s2.copy(g = gIns, h = h2)
                   .setConstrainable(constrainableWildcards, false)
        produce(s3, toSf(snap), body, pve, v1)((s4, v2) => {
          v2.decider.prover.saturate(Verifier.config.z3SaturationTimeouts.afterUnfold)
          val predicateTrigger =
            App(Verifier.predicateData(predicate).triggerFunction,
                snap.convert(terms.sorts.Snap) +: tArgs)
          v2.decider.assume(predicateTrigger)
          Q(s4.copy(g = s.g), v2)})
      })
      // profiling here?
    } else {
      val ve = pve dueTo InsufficientPermission(pa)
      val description = s"consume ${pa.pos}: $pa"

      val s3 = s1.copy(foldOrUnfoldAstNode = origin)

      // we attempt to consume the predicate from the heap
      chunkSupporter.consume(s3, s3.h, true, predicate, tArgs, s3.permissionScalingFactor, ve, v, description)((s4, h1, snap1, v1, chunkExisted) => {
          
          profilingInfo.incrementTotalConjuncts

          if (s4.isImprecise) {
            // and then we attempt to consume it from the optimistic heap
            chunkSupporter.consume(s4, s4.optimisticHeap, false, predicate, tArgs, s4.permissionScalingFactor, ve, v1, description)((s5, oh1, snap2, v2, chunkExisted1) => {
              if (!chunkExisted && chunkExisted1) {

                val runtimeCheckAstNode =
                  (s5.methodCallAstNode, s5.foldOrUnfoldAstNode, s5.loopPosition) match {
                    case (None, None, None) => CheckPosition.GenericNode(pa)
                    case (Some(methodCallAstNode), None, None) =>
                      CheckPosition.GenericNode(methodCallAstNode)
                    case (None, Some(foldOrUnfoldAstNode), None) =>
                      CheckPosition.GenericNode(foldOrUnfoldAstNode)
                    case (None, None, Some(loopPosition)) => loopPosition
                    case _ =>
                      sys.error("Conflicting positions while looking for position!")
                  }

                if (s5.generateChecks) {
                  runtimeChecks.addChecks(runtimeCheckAstNode,
                    ast.PredicateAccessPredicate(pa, ast.FullPerm()())(),
                    viper.silicon.utils.zip3(v2.decider.pcs.branchConditionsSemanticAstNodes,
                      v2.decider.pcs.branchConditionsAstNodes,
                      v.decider.pcs.branchConditionsOrigins).map(bc => BranchCond(bc._1, bc._2, bc._3)),
                    pa,
                    s5.forFraming)
                  pa.addCheck(ast.PredicateAccessPredicate(pa, ast.FullPerm()())())
                }
              }
              if (chunkExisted) {

                profilingInfo.incrementEliminatedConjuncts

                val s6 = s5.copy(g = gIns,
                                 frameArgHeap = Heap(),
                                 oldStore = Some(s5.g),
                                 oldHeaps = s5.oldHeaps + (Verifier.PRE_HEAP_LABEL -> s5.h) + (Verifier.PRE_OPTHEAP_LABEL -> s5.optimisticHeap),
                                 h = h1,
                                 optimisticHeap = oh1 + s5.frameArgHeap,
                                 needConditionFramingUnfold = true)
                          .setConstrainable(constrainableWildcards, false)
                // we produce the body (this is an unfold?)
                produce(s6, toSf(snap1), body, pve, v2)((s7, v3) => {
                  val s8 = s7.copy(foldOrUnfoldAstNode = None, needConditionFramingUnfold = false)
                  v3.decider.prover.saturate(Verifier.config.z3SaturationTimeouts.afterUnfold)
                  val predicateTrigger =
                    App(Verifier.predicateData(predicate).triggerFunction, snap1 +: tArgs)
                  v3.decider.assume(predicateTrigger)
                  val s9 = s8.copy(g = s5.g, oldStore = None, oldHeaps = s5.oldHeaps,
                    permissionScalingFactor = s.permissionScalingFactor)
                  Q(s9, v3)
                })
              } else {

                profilingInfo.incrementEliminatedConjuncts

                val s6 = s5.copy(g = gIns,
                                 frameArgHeap = Heap(),
                                 oldStore = Some(s5.g),
                                 oldHeaps = s5.oldHeaps + (Verifier.PRE_HEAP_LABEL -> s5.h) + (Verifier.PRE_OPTHEAP_LABEL -> s5.optimisticHeap),
                                 h = h1,
                                 optimisticHeap = oh1 + s5.frameArgHeap)
                          .setConstrainable(constrainableWildcards, false)
                produce(s6, toSf(snap2), body, pve, v2)((s7, v3) => {
                  //println(s"Unsetting unfold AST node in state: ${s7.foldOrUnfoldAstNode}")
                  val s8 = s7.copy(foldOrUnfoldAstNode = None)
                  v3.decider.prover.saturate(Verifier.config.z3SaturationTimeouts.afterUnfold)
                  val predicateTrigger =
                    App(Verifier.predicateData(predicate).triggerFunction, snap2 +: tArgs)
                  v3.decider.assume(predicateTrigger)
                  val s9 = s8.copy(g = s5.g, oldStore = None, oldHeaps = s5.oldHeaps,
                    permissionScalingFactor = s.permissionScalingFactor)
                  Q(s9, v3)
                })
              }
            })
          } else if (chunkExisted) {

            profilingInfo.incrementEliminatedConjuncts

            val s5 = s4.copy(g = gIns,
                             frameArgHeap = Heap(),
                             oldStore = Some(s4.g),
                             oldHeaps = s4.oldHeaps + (Verifier.PRE_HEAP_LABEL -> s4.h) + (Verifier.PRE_OPTHEAP_LABEL -> s4.optimisticHeap),
                             h = h1,
                             needConditionFramingUnfold = true)
                      .setConstrainable(constrainableWildcards, false)
            produce(s5, toSf(snap1), body, pve, v1)((s6, v2) => {
              val s7 = s6.copy(foldOrUnfoldAstNode = None, needConditionFramingUnfold = false)
              v2.decider.prover.saturate(Verifier.config.z3SaturationTimeouts.afterUnfold)
              val predicateTrigger =
                App(Verifier.predicateData(predicate).triggerFunction, snap1 +: tArgs)
              v2.decider.assume(predicateTrigger)
              val s8 = s7.copy(g = s4.g, oldStore = None, oldHeaps = s4.oldHeaps,
                permissionScalingFactor = s.permissionScalingFactor)
              Q(s8, v2)
            })
          } else {
            createFailure(ve, v1, s4)
          }
      })
    }
  }

/* NOTE: Possible alternative to storing the permission scaling factor in the context
 *       or passing it to produce/consume as an explicit argument.
 *       Carbon uses Permissions.multiplyExpByPerm as well (but does not extend the
 *       store).
 */
//    private def scale(γ: ST, body: ast.Exp, perm: Term) = {
//      /* TODO: Ensure that variable name does not clash with any Silver identifier already in use */
//      val scaleFactorVar = ast.LocalVar(identifierFactory.fresh("p'unf").name)(ast.Perm)
//      val scaledBody = ast.utility.Permissions.multiplyExpByPerm(body, scaleFactorVar)
//
//      (γ + (scaleFactorVar -> perm), scaledBody)
//    }
}
