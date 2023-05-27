// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2011-2019 ETH Zurich.

package viper.silicon.rules

import scala.collection.mutable
import viper.silver.ast
import viper.silver.ast.utility.QuantifiedPermissions.QuantifiedPermissionAssertion
import viper.silver.verifier.PartialVerificationError
import viper.silver.verifier.reasons._
import viper.silicon.Stack
import viper.silicon.interfaces.{Failure, VerificationResult}
import viper.silicon.state._
import viper.silicon.state.terms._
import viper.silicon.state.terms.predef.`?r`
import viper.silicon.supporters.Translator
import viper.silicon.verifier.Verifier
import viper.silicon.{ConsumeRecord, GlobalBranchRecord, SymbExLogger}
import viper.silicon.utils

trait ConsumptionRules extends SymbolicExecutionRules {

  /** Consume assertion `a` from state `s`.
    *
    * @param s The state to consume the assertion from.
    * @param a The assertion to consume.
    * @param pve The error to report in case the consumption fails.
    * @param v The verifier to use.
    * @param Q The continuation to invoke if the consumption succeeded, with the following
    *          arguments: state (1st argument) and verifier (3rd argument) resulting from the
    *          consumption, and a heap snapshot (2bd argument )representing the values of the
    *          consumed partial heap.
    * @return The result of the continuation.
    */
  def consume(s: State, a: ast.Exp, pve: PartialVerificationError, v: Verifier)
             (Q: (State, Term, Verifier) => VerificationResult)
             : VerificationResult

  /** Subsequently consumes the assertions `as` (from head to tail), starting in state `s`.
    *
    * `consumes(s, as, _ => pve, v)` should (not yet tested ...) be equivalent to
    * `consume(s, BigAnd(as), pve, v)`, expect that the former allows a more-fine-grained
    * error messages.
    *
    * @param s The state to consume the assertions from.
    * @param as The assertions to consume.
    * @param pvef The error to report in case a consumption fails. Given assertions `as`, an error
    *             `pvef(as_i)` will be reported if consuming assertion `as_i` fails.
    * @param v @see [[consume]]
    * @param Q @see [[consume]]
    * @return @see [[consume]]
    */
  def consumes(s: State,
               as: Seq[ast.Exp],
               pvef: ast.Exp => PartialVerificationError,
               v: Verifier)
              (Q: (State, Term, Verifier) => VerificationResult)
              : VerificationResult
}

object consumer extends ConsumptionRules with Immutable {
  import brancher._
  import evaluator._

  /* See the comment in Producer.scala for an overview of the different produce methods: the
   * different consume methods provided by the consumer work and interact analogously.
   */

  /** @inheritdoc */
  def consume(s: State, a: ast.Exp, pve: PartialVerificationError, v: Verifier)
             (Q: (State, Term, Verifier) => VerificationResult)
             : VerificationResult = {

    val consumed = a match {
      case impr @ ast.ImpreciseExp(e) =>
        consumeR(s, true, s.optimisticHeap, s.h, e.whenExhaling, pve, v)((s1, oh1, h1, snap, v1) => {
          val s2 = s1.copy(isImprecise = true, h = Heap(), optimisticHeap = Heap(),
                           partiallyConsumedHeap = s.partiallyConsumedHeap)
          Q(s2, Combine(Unit, snap), v1)})

      case _ =>
        consumeR(s, s.isImprecise, s.optimisticHeap, s.h, a.whenExhaling, pve, v)((s1, oh1, h1, snap, v1) => {
          val s2 = s1.copy(h = h1, optimisticHeap = oh1,
                           partiallyConsumedHeap = s.partiallyConsumedHeap)
          Q(s2, snap, v1)})
    }
    consumed
  }


  /** @inheritdoc */
  def consumes(s: State,
               as: Seq[ast.Exp],
               pvef: ast.Exp => PartialVerificationError,
               v: Verifier)
              (Q: (State, Term, Verifier) => VerificationResult)
              : VerificationResult = {

    val allTlcs = mutable.ListBuffer[ast.Exp]()
    val allPves = mutable.ListBuffer[PartialVerificationError]()

    var imprecise = false

  //  println("as: " + as)
    as.foreach(a => {
    //  println("a: " + a.whenExhaling.topLevelConjuncts)
      a match {
        // if a is an imprecise expression we add all the expressions
        // within it to our list ltcs's
        case impr @ ast.ImpreciseExp(e) =>
          imprecise = true
          val exps = e.whenExhaling.topLevelConjuncts
          exps.foreach(exp => {
      //      println("exp: " + exp)
            val tlcs = exp.whenExhaling.topLevelConjuncts
            val pves = Seq.fill(tlcs.length)(pvef(exp))

            allTlcs ++= tlcs
            allPves ++= pves

          })
        case _ =>
          val tlcs = a.whenExhaling.topLevelConjuncts
          val pves = Seq.fill(tlcs.length)(pvef(a))

          allTlcs ++= tlcs
          allPves ++= pves
      }
    })

//    println("tlcs: " + allTlcs)
//    println("tlcs result: " + allTlcs.result())


    if(imprecise) {
      consumeTlcs(s, true, s.optimisticHeap, s.h, allTlcs.result(), allPves.result(), v)((s1, oh1, h1, snap1, v1) => {
        val s2 = s1.copy(h = Heap(),
                        optimisticHeap = Heap(),
                        partiallyConsumedHeap = s.partiallyConsumedHeap,
                        isImprecise = true)
        Q(s2, Combine(Unit, snap1), v1)
      })
    } else {
      consumeTlcs(s, s.isImprecise, s.optimisticHeap, s.h, allTlcs.result(), allPves.result(), v)((s1, oh1, h1, snap1, v1) => {
        val s2 = s1.copy(h = h1,
                        optimisticHeap = oh1,
                        partiallyConsumedHeap = s.partiallyConsumedHeap)
        Q(s2, snap1, v1)
      })
    }
  }
/*
    consumeTlcs(s, s.h, allTlcs.result(), allPves.result(), v)((s1, h1, snap1, v1) => {
      val s2 = s1.copy(h = h1,
                       partiallyConsumedHeap = s.partiallyConsumedHeap)
      Q(s2, snap1, v1)
    })
  }
*/
  private def consumeTlcs(s: State,
                          impr: Boolean,
                          oh: Heap,
                          h: Heap,
                          tlcs: Seq[ast.Exp],
                          pves: Seq[PartialVerificationError],
                          v: Verifier)
                         (Q: (State, Heap, Heap, Term, Verifier) => VerificationResult)
                         : VerificationResult = {

    if (tlcs.isEmpty)
      Q(s, oh, h, Unit, v)
    else {
      val a = tlcs.head
      val pve = pves.head


      if (tlcs.tail.isEmpty)
        wrappedConsumeTlc(s, impr, oh, h, a, pve, v)(Q)
      else
        wrappedConsumeTlc(s, impr, oh, h, a, pve, v)((s1, oh1, h1, snap1, v1) =>
          consumeTlcs(s1, impr, oh1, h1, tlcs.tail, pves.tail, v1)((s2, oh2, h2, snap2, v2) =>
            Q(s2, oh2, h2, Combine(snap1, snap2), v2)))
    }
  }

  private def consumeR(s: State, impr: Boolean, oh: Heap, h: Heap, a: ast.Exp, pve: PartialVerificationError, v: Verifier)
                      (Q: (State, Heap, Heap, Term, Verifier) => VerificationResult)
                      : VerificationResult = {

    val tlcs = a.topLevelConjuncts
    val pves = Seq.fill(tlcs.length)(pve)

    consumeTlcs(s, impr, oh, h, tlcs, pves, v)(Q)
  }

  /** Wrapper/decorator for consume that injects the following operations:
    *   - Logging, see Executor.scala for an explanation
    *   - Failure-driven state consolidation
    */
  protected def wrappedConsumeTlc(s: State,
                                  impr: Boolean,
                                  oh: Heap,
                                  h: Heap,
                                  a: ast.Exp,
                                  pve: PartialVerificationError,
                                  v: Verifier)
                                 (Q: (State, Heap, Heap, Term, Verifier) => VerificationResult)
                                 : VerificationResult = {
// Do we need to do this stuff on oh? - Jacob
    /* tryOrFail effects the "main" heap s.h, so we temporarily set the consume-heap h to be the
     * main heap. Note that the main heap is used for evaluating expressions during an ongoing
     * consume.
     */
    val sInit = s.copy(h = h)
    val s0 = stateConsolidator.consolidate(sInit, v)
    val h0 = s0.h /* h0 is h, but consolidated */
    val s1 = s0.copy(h = s.h)

    /* TODO: To remove this cast: Add a type argument to the ConsumeRecord.
     *       Globally the types match, but locally the type system does not know.
     */
    val SEP_identifier = SymbExLogger.currentLog().insert(new ConsumeRecord(a, s1, v.decider.pcs))
    consumeTlc(s1, impr, oh, h0, a, pve, v)((s2, oh2, h2, snap2, v1) => {
      SymbExLogger.currentLog().collapse(a, SEP_identifier)
      Q(s2, oh2, h2, snap2, v1)})
  }

  private def consumeTlc(s: State, impr: Boolean, oh: Heap, h: Heap, a: ast.Exp, pve: PartialVerificationError, v: Verifier)
                        (Q: (State, Heap, Heap, Term, Verifier) => VerificationResult)
                        : VerificationResult = {
    
    /* ATTENTION: Expressions such as `perm(...)` must be evaluated in-place,
     * i.e. in the partially consumed heap which is denoted by `h` here. The
     * evaluator evaluates such expressions in the heap
     * `context.partiallyConsumedHeap`. Hence, this field must be updated every
     * time permissions have been consumed.
     */

    v.logger.debug(s"\nCONSUME ${viper.silicon.utils.ast.sourceLineColumn(a)}: $a")
    v.logger.debug(v.stateFormatter.format(s, v.decider.pcs))
    v.logger.debug("h = " + v.stateFormatter.format(h))
    if (s.reserveHeaps.nonEmpty)
      v.logger.debug("hR = " + s.reserveHeaps.map(v.stateFormatter.format).mkString("", ",\n     ", ""))

    val consumed = a match {

/*
      case imp @ ast.Implies(e0, a0) if !a.isPure =>
        val impLog = new GlobalBranchRecord(imp, s, v.decider.pcs, "consume")
        val sepIdentifier = SymbExLogger.currentLog().insert(impLog)
        SymbExLogger.currentLog().initializeBranching()

        evaluator.eval(s, e0, pve, v)((s1, t0, v1) => {
          impLog.finish_cond()
          val branch_res =
            branch(s1, t0, v1)(
              (s2, v2) => consumeR(s2, h, a0, pve, v2)((s3, h3, snap3, v3) => {
                val res1 = Q(s3, h3, snap3, v3)
                impLog.finish_thnSubs()
                SymbExLogger.currentLog().prepareOtherBranch(impLog)
                res1}),
              (s2, v2) => {
                val res2 = Q(s2, h, Unit, v2)
                impLog.finish_elsSubs()
                res2})
          SymbExLogger.currentLog().collapse(null, sepIdentifier)
          branch_res})
*/
      // this would be invoked on a precondition? after the method call site is
      // encountered i think
      
      // consume the method call ast node attached to the state for
      // preconditions here

      // IMPORTANT: entering this method should remove that ast node from the
      // state, that is, we should set it to None(?)
      //
      // set some local variable, sourceCall, so we can continue to access it?
      case ite @ ast.CondExp(e0, a1, a2) =>
        val gbLog = new GlobalBranchRecord(ite, s, v.decider.pcs, "consume")
        val sepIdentifier = SymbExLogger.currentLog().insert(gbLog)
        SymbExLogger.currentLog().initializeBranching()
        evalpc(s.copy(isImprecise = impr), e0, pve, v)((s1, t0, v1) => {
          val s2 = s1.copy(isImprecise = s.isImprecise)
          gbLog.finish_cond()
          val branch_res = {
      
            // what was happening here...?
            // we were unsetting the position in the state at the beginning of
            // consumeTlc, but we were not able to attach it to the branching info
            //
            // we weren't seeing it at this point, where we were matching on it to see if
            // it was None
            //
            // this has been changed since that point, but we should figure out what the
            // issue was... it is commit with the message "Buggy changes to track branch positions
            // for method call sites"
            val branchPosition: Option[CheckPosition] =
              (s.methodCallAstNode, s.foldOrUnfoldAstNode, s.loopPosition) match {
                case (None, None, None) => None
                case (Some(methodCallAstNode), None, None) => Some(CheckPosition.GenericNode(methodCallAstNode))
                case (None, Some(foldOrUnfoldAstNode), None) => Some(CheckPosition.GenericNode(foldOrUnfoldAstNode))
                case (None, None, Some(_)) => s.loopPosition
                case _ => {
                  sys.error("This should not happen, at least until we support "
                    + "unfoldings, maybe! We don't deal with this case at the "
                    + "moment because we want to know if this happens!")
                }
              }

            branch(s2, t0, e0, branchPosition, v1)(
              // the things in the branch (the then and else contents) may reach
              // the final case of consumeTlc, where we unset the method
              // callsite ast node
              //
              // that's why it worked before...? the way we do it now is
              // better, maybe
              (s3, v2) => consumeR(s3, impr, oh, h, a1, pve, v2)((s4, oh3, h3, snap3, v3) => {
                val res1 = Q(s4, oh3, h3, snap3, v3)
                gbLog.finish_thnSubs()
                SymbExLogger.currentLog().prepareOtherBranch(gbLog)
                res1}),
              (s3, v2) => consumeR(s3, impr, oh, h, a2, pve, v2)((s4, oh3, h3, snap3, v3) => {
                val res2 = Q(s4, oh3, h3, snap3, v3)
                gbLog.finish_elsSubs()
                res2}))
          }
          SymbExLogger.currentLog().collapse(null, sepIdentifier)
          branch_res})

      /* TODO: Initial handling of QPs is identical/very similar in consumer
       *       and producer. Try to unify the code.
       */

/*
      case QuantifiedPermissionAssertion(forall, cond, acc: ast.FieldAccessPredicate) =>
        val field = acc.loc.field
        val qid = BasicChunkIdentifier(acc.loc.field.name)
        val optTrigger =
          if (forall.triggers.isEmpty) None
          else Some(forall.triggers)
        evalQuantified(s, Forall, forall.variables, Seq(cond), Seq(acc.perm, acc.loc.rcv), optTrigger, qid.name, pve, v) {
          case (s1, qvars, Seq(tCond), Seq(tPerm, tRcvr), tTriggers, (auxGlobals, auxNonGlobals), v1) =>
            quantifiedChunkSupporter.consume(
              s = s1,
              h = h,
              forall = forall,
              acc = acc,
              resource = field,
              qvars = qvars,
              formalQVars = Seq(`?r`),
              qid = qid.name,
              optTrigger = optTrigger,
              tTriggers = tTriggers,
              auxGlobals = auxGlobals,
              auxNonGlobals = auxNonGlobals,
              tCond = tCond,
              tArgs = Seq(tRcvr),
              tPerm = tPerm,
              pve = pve,
              negativePermissionReason = NegativePermission(acc.perm),
              notInjectiveReason = ReceiverNotInjective(acc.loc),
              insufficientPermissionReason =InsufficientPermission(acc.loc),
              v1)(Q)
        }

      case QuantifiedPermissionAssertion(forall, cond, acc: ast.PredicateAccessPredicate) =>
        val predicate = Verifier.program.findPredicate(acc.loc.predicateName)
         * TODO: Quantified codomain variables are used in axioms and chunks (analogous to `?r`)
         *       and need to be instantiated in several places. Hence, they need to be known,
         *       which is more complicated if fresh identifiers are used.
         *       At least two options:
         *         1. Choose fresh identifiers each time; remember/restore, e.g. by storing these variables in chunks
         *         2. Choose fresh identifiers once; store in and take from state (or from object Verifier)
         *
        val formalVars = s.predicateFormalVarMap(predicate)
        val qid = BasicChunkIdentifier(acc.loc.predicateName)
        val optTrigger =
          if (forall.triggers.isEmpty) None
          else Some(forall.triggers)
        evalQuantified(s, Forall, forall.variables, Seq(cond), acc.perm +: acc.loc.args, optTrigger, qid.name, pve, v) {
          case (s1, qvars, Seq(tCond), Seq(tPerm, tArgs @ _*), tTriggers, (auxGlobals, auxNonGlobals), v1) =>
            quantifiedChunkSupporter.consume(
              s = s1,
              h = h,
              forall = forall,
              acc = acc,
              resource = predicate,
              qvars = qvars,
              formalQVars = formalVars,
              qid = qid.name,
              optTrigger = optTrigger,
              tTriggers = tTriggers,
              auxGlobals = auxGlobals,
              auxNonGlobals = auxNonGlobals,
              tCond = tCond,
              tArgs = tArgs,
              tPerm = tPerm,
              pve = pve,
              negativePermissionReason = NegativePermission(acc.perm),
              notInjectiveReason = ReceiverNotInjective(acc.loc),
              insufficientPermissionReason =InsufficientPermission(acc.loc),
              v1)(Q)
        }

      case QuantifiedPermissionAssertion(forall, cond, wand: ast.MagicWand) =>
        val bodyVars = wand.subexpressionsToEvaluate(Verifier.program)
        val formalVars = bodyVars.indices.toList.map(i => Var(Identifier(s"x$i"), v.symbolConverter.toSort(bodyVars(i).typ)))
        val qid = MagicWandIdentifier(wand, Verifier.program).toString
        val optTrigger =
          if (forall.triggers.isEmpty) None
          else Some(forall.triggers)
        val ePerm = ast.FullPerm()()
        val tPerm = FullPerm()
        evalQuantified(s, Forall, forall.variables, Seq(cond), bodyVars, optTrigger, qid, pve, v) {
          case (s1, qvars, Seq(tCond), tArgs, tTriggers, (auxGlobals, auxNonGlobals), v1) =>
            quantifiedChunkSupporter.consume(
              s = s1,
              h = h,
              forall = forall,
              acc = wand,
              resource = wand,
              qvars = qvars,
              formalQVars = formalVars,
              qid = qid,
              optTrigger = optTrigger,
              tTriggers = tTriggers,
              auxGlobals = auxGlobals,
              auxNonGlobals = auxNonGlobals,
              tCond = tCond,
              tArgs = tArgs,
              tPerm = tPerm,
              pve = pve,
              negativePermissionReason = NegativePermission(ePerm),
              notInjectiveReason = sys.error("Quantified wand not injective"), /*ReceiverNotInjective(...)*/
              insufficientPermissionReason = MagicWandChunkNotFound(wand), /*InsufficientPermission(...)*/
              v1)(Q)
        }
*/
/*
      case ast.AccessPredicate(loc @ ast.FieldAccess(eRcvr, field), ePerm)
              if s.qpFields.contains(field) =>

        eval(s, eRcvr, pve, v)((s1, tRcvr, v1) =>
          eval(s1, ePerm, pve, v1)((s2, tPerm, v2) => {
            val (relevantChunks, _) =
              quantifiedChunkSupporter.splitHeap[QuantifiedFieldChunk](s2.h, BasicChunkIdentifier(field.name))
            val (smDef1, smCache1) =
              quantifiedChunkSupporter.summarisingSnapshotMap(
                s2, field, Seq(`?r`), relevantChunks, v2)
            v2.decider.assume(FieldTrigger(field.name, smDef1.sm, tRcvr))
//            v2.decider.assume(PermAtMost(tPerm, FullPerm()))
            val loss = PermTimes(tPerm, s2.permissionScalingFactor)
            quantifiedChunkSupporter.consumeSingleLocation(
              s2.copy(smCache = smCache1),
              h,
              Seq(`?r`),
              Seq(tRcvr),
              loc,
              loss,
              None,
              pve,
              v2
            )((s3, h3, snap, v3) => {
              val s4 = s3.copy(constrainableARPs = s1.constrainableARPs,
                               partiallyConsumedHeap = Some(h3))
              Q(s4, oh, h3, snap, v3)})}))

      case ast.AccessPredicate(loc @ ast.PredicateAccess(eArgs, predname), ePerm)
              if s.qpPredicates.contains(Verifier.program.findPredicate(predname)) =>

        val predicate = Verifier.program.findPredicate(predname)
        val formalVars = s.predicateFormalVarMap(predicate)

        evals(s, eArgs, _ => pve, v)((s1, tArgs, v1) =>
          eval(s1, ePerm, pve, v1)((s2, tPerm, v2) => {
            val (relevantChunks, _) =
              quantifiedChunkSupporter.splitHeap[QuantifiedPredicateChunk](s.h, BasicChunkIdentifier(predname))
            val (smDef1, smCache1) =
              quantifiedChunkSupporter.summarisingSnapshotMap(
                s2, predicate, s2.predicateFormalVarMap(predicate), relevantChunks, v2)
            v2.decider.assume(PredicateTrigger(predicate.name, smDef1.sm, tArgs))

            val loss = PermTimes(tPerm, s2.permissionScalingFactor)
            quantifiedChunkSupporter.consumeSingleLocation(
              s2.copy(smCache = smCache1),
              h,
              formalVars,
              tArgs,
              loc,
              loss,
              None,
              pve,
              v2
            )((s3, h3, snap, v3) => {
              val s4 = s3.copy(constrainableARPs = s1.constrainableARPs,
                               partiallyConsumedHeap = Some(h3))
              Q(s4, oh, h3, snap, v3)})}))
*/

/*
      case let: ast.Let if !let.isPure =>
        letSupporter.handle[ast.Exp](s, let, pve, v)((s1, g1, body, v1) => {
          val s2 = s1.copy(g = s1.g + g1)
          consumeR(s2, impr, oh, h, body, pve, v1)(Q)})
*/
/*
      case ast.AccessPredicate(locacc: ast.LocationAccess, perm) =>
        eval(s, perm, pve, v)((s1, tPerm, v1) =>
          evalLocationAccesspc(s1.copy(isImprecise = impr), locacc, pve, v1)((s2, _, tArgs, v2) =>
            v2.decider.assert(perms.IsNonNegative(tPerm)){
              case true =>
                val resource = locacc.res(Verifier.program)
                val loss = PermTimes(tPerm, s2.permissionScalingFactor)
                val ve = pve dueTo InsufficientPermission(locacc)
                val description = s"consume ${a.pos}: $a"
                chunkSupporter.consume(s2, h, resource, tArgs, loss, ve, v2, description)((s3, h1, snap1, v3) => {
                  val s4 = s3.copy(partiallyConsumedHeap = Some(h1),
                                   constrainableARPs = s.constrainableARPs,
                                   isImprecise = s3.isImprecise)
                  *
                  if (s4.isImprecise) {
                    //heaprem a.k.a. .consume
                    //Q()
                  } else if () {

                  } else {
                    //create failure
                  }

                  *
                  Q(s4, h1, snap1, v3)})
              case false =>
                createFailure(pve dueTo NegativePermission(perm), v2, s2)}))
*/
      case ast.PredicateAccessPredicate(locacc: ast.LocationAccess, perm) =>

       //eval for expression and perm (perm should always be 1)
        evalpc(s.copy(isImprecise = impr), perm, pve, v)((s1, tPerm, v1) =>
          evalLocationAccesspc(s1.copy(isImprecise = impr), locacc, pve, v1)((s2, predName, tArgs, v2) => {
            v2.decider.assertgv(s.isImprecise, perms.IsPositive(tPerm)) {
              case true =>
                val resource = locacc.res(Verifier.program)
                val loss = PermTimes(tPerm, s2.permissionScalingFactor)
                val ve = pve dueTo InsufficientPermission(locacc)
                val description = s"consume ${a.pos}: $a"
                var s3 = s2.copy(isImprecise = s.isImprecise)

                chunkSupporter.consume(s3, h, true, resource, tArgs, loss, ve, v2, description)((s4, h1, snap1, v3, chunkExisted) => {

                  profilingInfo.incrementTotalConjuncts

                  if (s4.isImprecise) {
                    chunkSupporter.consume(s4, oh, false, resource, tArgs, loss, ve, v3, description)((s5, oh1, snap2, v4, chunkExisted1) => {
                      
                      if (!chunkExisted && !chunkExisted1) {
                        
                        val runtimeCheckAstNode: CheckPosition =
                          (s5.methodCallAstNode, s5.foldOrUnfoldAstNode, s5.loopPosition) match {
                            case (None, None, None) => CheckPosition.GenericNode(a)
                            case (Some(methodCallAstNode), None, None) => CheckPosition.GenericNode(methodCallAstNode)
                            case (None, Some(foldOrUnfoldAstNode), None) => CheckPosition.GenericNode(foldOrUnfoldAstNode)
                            case (None, None, Some(loopPosition)) => loopPosition
                            case _ => sys.error("Conflicting positions found while producing runtime check!")
                          }

                        val g = s5.oldStore match {
                          case Some(g) => g
                          case None => s5.g
                        }
                        val translatedArgs: Seq[ast.Exp] =
                          tArgs.map(tArg => new Translator(s5.copy(g = g), v4.decider.pcs).translate(tArg) match {
                            case None => sys.error("Error translating! Exiting safely.")
                            case Some(expr) => expr
                          })

                        if (s5.generateChecks) {
                          runtimeChecks.addChecks(runtimeCheckAstNode,
                            ast.PredicateAccessPredicate(ast.PredicateAccess(translatedArgs, predName)(), perm)(),
                            viper.silicon.utils.zip3(v4.decider.pcs.branchConditionsSemanticAstNodes,
                              v4.decider.pcs.branchConditionsAstNodes,
                              v.decider.pcs.branchConditionsOrigins).map(bc => BranchCond(bc._1, bc._2, bc._3)),
                            a,
                            s5.forFraming)
                        }
                      }

                      if (chunkExisted) {
                        
                        profilingInfo.incrementEliminatedConjuncts

                        Q(s5, oh1, h1, snap1, v4)}

                      else {

                        if (chunkExisted1) {
                          profilingInfo.incrementEliminatedConjuncts
                        }

                        Q(s5, oh1, h1, snap2, v4)}})}

                  else if (chunkExisted) {

                    profilingInfo.incrementEliminatedConjuncts

                    Q(s4, oh, h1, snap1, v3)}

                  else {

                    createFailure(pve dueTo InsufficientPermission(locacc), v3, s4)}})

              case false =>

                createFailure(pve dueTo InsufficientPermission(locacc), v2, s2)

            } match {

              case (verificationResult, _) => verificationResult

            }}))


      case ast.FieldAccessPredicate(locacc: ast.LocationAccess, perm) =>

       //eval for expression and perm (perm should always be 1)
        evalpc(s.copy(isImprecise = impr), perm, pve, v)((s1, tPerm, v1) =>
          evalLocationAccesspc(s1.copy(isImprecise = impr), locacc, pve, v1)((s2, field, tArgs, v2) => {
            // is this why we produce a runtime check for != Null? does the
            // path condition not imply this (no, apparently it does not, at least for the
            // extra_check_issue.vpr example)
            v2.decider.assertgv(s.isImprecise, And(perms.IsPositive(tPerm), tArgs.head !== Null())){
              case true =>
                val resource = locacc.res(Verifier.program)
                val loss = PermTimes(tPerm, s2.permissionScalingFactor)
                val ve = pve dueTo InsufficientPermission(locacc)
                val description = s"consume ${a.pos}: $a"
                var s3 = s2.copy(isImprecise = s.isImprecise)

                chunkSupporter.consume(s3, h, true, resource, tArgs, loss, ve, v2, description)((s4, h1, snap1, v3, chunkExisted) => {

                  profilingInfo.incrementTotalConjuncts

                  // don't know if this should be s3 or s4 - J
                  if (s4.isImprecise) {
                    chunkSupporter.consume(s4, oh, false, resource, tArgs, loss, ve, v3, description)((s5, oh1, snap2, v4, chunkExisted1) => {
                      
                      if (!chunkExisted && !chunkExisted1) {

                        val runtimeCheckAstNode: CheckPosition =
                          (s5.methodCallAstNode, s5.foldOrUnfoldAstNode, s5.loopPosition) match {
                            case (None, None, None) => CheckPosition.GenericNode(locacc)
                            case (Some(methodCallAstNode), None, None) =>
                              CheckPosition.GenericNode(methodCallAstNode)
                            case (None, Some(foldOrUnfoldAstNode), None) =>
                              CheckPosition.GenericNode(foldOrUnfoldAstNode)
                            case (None, None, Some(loopPosition)) => loopPosition
                            case _ => sys.error("Conflicting positions!")
                          }

                        val g = s5.oldStore match {
                          case Some(g) => g
                          case None => s5.g
                        }
                        val translatedArgs: Seq[ast.Exp] =
                          tArgs.map(tArg => new Translator(s5.copy(g = g), v4.decider.pcs).translate(tArg) match {
                            case None => sys.error("Error translating! Exiting safely.")
                            case Some(expr) => expr
                          })

                        if (s5.generateChecks) {
                          runtimeChecks.addChecks(runtimeCheckAstNode,
                            ast.FieldAccessPredicate(ast.FieldAccess(translatedArgs.head, resource.asInstanceOf[ast.Field])(), perm)(),
                            viper.silicon.utils.zip3(v4.decider.pcs.branchConditionsSemanticAstNodes,
                              v4.decider.pcs.branchConditionsAstNodes,
                              v.decider.pcs.branchConditionsOrigins).map(bc => BranchCond(bc._1, bc._2, bc._3)),
                            a,
                            s5.forFraming)
                        }
                      }

                      if (chunkExisted) {

                        profilingInfo.incrementEliminatedConjuncts
                        Q(s5, oh1, h1, snap1, v4)}

                      else {

                        // we don't want to count it if the runtime check
                        // path happened, i think
                        if (chunkExisted1) {
                          profilingInfo.incrementEliminatedConjuncts
                        }

                        Q(s5, oh1, h1, snap2, v4)}})}
                  else if (chunkExisted) {
                    profilingInfo.incrementEliminatedConjuncts
                    Q(s4, oh, h1, snap1, v3)}
                  else {
                    createFailure(pve dueTo InsufficientPermission(locacc), v3, s4)}})

              case false =>
                createFailure(pve dueTo InsufficientPermission(locacc), v2, s2)

            // this is the assertgv case for field access
            } match {
                case (verificationResult, potentialReturnedChecks) => {
                  potentialReturnedChecks match {
                    case None => ()
                    case Some(returnedChecks) => {
                      // should use v2.decider.pcs here? yes

                      val runtimeCheckAstNode: CheckPosition =
                        (s2.methodCallAstNode, s2.foldOrUnfoldAstNode, s2.loopPosition) match {
                          case (None, None, None) => CheckPosition.GenericNode(a)
                          case (Some(methodCallAstNode), None, None) =>
                            CheckPosition.GenericNode(methodCallAstNode)
                          case (None, Some(foldOrUnfoldAstNode), None) => CheckPosition.GenericNode(foldOrUnfoldAstNode)
                          case (None, None, Some(loopPosition)) => loopPosition
                          case _ =>
                            sys.error("Conflicting positions while looking for position!")
                        }

                      val g = s2.oldStore match {
                        case Some(g) => g
                        case None => s2.g
                      }

                      if (s2.generateChecks) {
                        runtimeChecks.addChecks(runtimeCheckAstNode,
                          (new Translator(s2.copy(g = g), v2.decider.pcs).translate(returnedChecks) match {
                            case None => sys.error("Error translating! Exiting safely.")
                            case Some(expr) => expr
                          }),
                        viper.silicon.utils.zip3(v2.decider.pcs.branchConditionsSemanticAstNodes,
                          v2.decider.pcs.branchConditionsAstNodes,
                          v2.decider.pcs.branchConditionsOrigins).map(bc => BranchCond(bc._1, bc._2, bc._3)),
                        a,
                        s2.forFraming)
                      }
                    }
                  }
                  verificationResult
                }
            }}))

/*
      case ast.AccessPredicate(locacc: ast.LocationAccess, perm/*,need an overloaded copy with impreciseHeap as a parameter*/) => //add h_?; perm = 1

       //eval for expression and perm (perm should always be 1)
        evalpc(s.copy(isImprecise = impr), perm, pve, v)((s1, tPerm, v1) =>
          evalLocationAccesspc(s1.copy(isImprecise = impr), locacc, pve, v1)((s2, _, tArgs, v2) => {

            v2.decider.assertgv(s.isImprecise, perms.IsPositive(tPerm)){
              case true =>
                val resource = locacc.res(Verifier.program)
                val loss = PermTimes(tPerm, s2.permissionScalingFactor)
                val ve = pve dueTo InsufficientPermission(locacc)
                val description = s"consume ${a.pos}: $a"
                var s3 = s2.copy(isImprecise = s.isImprecise)



                chunkSupporter.consume(s3, h, resource, tArgs, loss, ve, v2, description)((s4, h1, snap1, v3, chunkExisted) => {
/*                  val s4 = s3.copy(partiallyConsumedHeap = Some(h1),
                                   constrainableARPs = s.constrainableARPs,
                                   isImprecise = s3.isImprecise)
  */
/*                  if (s4.isImprecise) {
                    //do we want to use s3 or s4 here?
                    //heaprem a.k.a. .consume
                    //Q()
                  } else if () {

                  } else {
                    //create failure
                  }

*/
                  Q(s4, oh, h1, snap1, v3)})
              case false =>
                createFailure(pve dueTo InsufficientPermission(locacc), v2, s2)}}))
*/
/*
      case _: ast.InhaleExhaleExp =>
        Failure(viper.silicon.utils.consistency.createUnexpectedInhaleExhaleExpressionError(a))
*/
      /* Handle wands */

/*
      case wand: ast.MagicWand if s.qpMagicWands.contains(MagicWandIdentifier(wand, Verifier.program)) =>
        val bodyVars = wand.subexpressionsToEvaluate(Verifier.program)
        val formalVars = bodyVars.indices.toList.map(i => Var(Identifier(s"x$i"), v.symbolConverter.toSort(bodyVars(i).typ)))

        evals(s, bodyVars, _ => pve, v)((s1, tArgs, v1) => {
          val (relevantChunks, _) =
            quantifiedChunkSupporter.splitHeap[QuantifiedMagicWandChunk](s1.h, MagicWandIdentifier(wand, Verifier.program))
          val (smDef1, smCache1) =
            quantifiedChunkSupporter.summarisingSnapshotMap(
              s1, wand, formalVars, relevantChunks, v1)
          v1.decider.assume(PredicateTrigger(MagicWandIdentifier(wand, Verifier.program).toString, smDef1.sm, tArgs))

          val loss = PermTimes(FullPerm(), s1.permissionScalingFactor)
          quantifiedChunkSupporter.consumeSingleLocation(
            s1.copy(smCache = smCache1),
            h,
            formalVars,
            tArgs,
            wand,
            loss,
            None,
            pve,
            v1
          )((s3, h3, snap, v3) => {
            val s4 = s3.copy(constrainableARPs = s1.constrainableARPs,
                             partiallyConsumedHeap = Some(h3))
            Q(s4, h3, snap, v3)})})

      case wand: ast.MagicWand =>
        magicWandSupporter.evaluateWandArguments(s, wand, pve, v)((s1, tArgs, v1) => {
          val ve = pve dueTo MagicWandChunkNotFound(wand)
          val description = s"consume wand $wand"
          chunkSupporter.consume(s1, h, wand, tArgs, FullPerm(), ve, v1, description)(Q)
        })
*/
      case _ => {

        var returnedState: Option[(State, viper.silicon.decider.RecordedPathConditions)] = None

        // make sure we map the runtime check from the method call site, if
        // we're currently looking at a precondition... otherwise, just use
        // the ast node passed into consumeTlc
        //
        // should we check for a fold or unfold statement here, too?
        //
        // we want to map the runtime check from the fold or unfold statement,
        // not something in the body of a predicate
        var runtimeCheckAstNode: CheckPosition = (s.methodCallAstNode, s.foldOrUnfoldAstNode, s.loopPosition) match {
          case (None, None, None) => CheckPosition.GenericNode(a)
          case (Some(methodCallAstNode), None, None) =>
            CheckPosition.GenericNode(methodCallAstNode)
          case (None, Some(foldOrUnfoldAstNode), None) => CheckPosition.GenericNode(foldOrUnfoldAstNode)
          case (None, None, Some(loopPosition)) => loopPosition

          // TODO: This should not occur, but it did at one point. Figure out why?
          case _ =>
            sys.error("Conflicting positions while looking for position! "
              + s"Position: ${(s.methodCallAstNode, s.foldOrUnfoldAstNode, s.loopPosition)}")
        }

        evalAndAssert(s, impr, a, pve, v)((s1, t, v1) => {

          returnedState = Some((s1, v1.decider.pcs.duplicate()))

          // the methodCallAstNode field should only stick around until we
          // consume the precondition of the method, right? we unset it here if
          // it exists, and after encountering a method call ast node, we must
          // go here (and nowhere else?)? we also only use this field here
          //
          // this is (partially?) wrong; we should really unset the field in
          // the state at the beginning of the method... though everything in a
          // precondition must(?) go through this case eventually, so that may
          // be why the previous version appeared to work fine

          Q(s1, oh, h, t, v1)
        }) match {
          case (verificationResult, Some(returnedChecks)) =>
            returnedState match {
              case Some((s1, pcs)) => {
                val g = s1.oldStore match {
                  case Some(g) => g
                  case None => s1.g
                }

                if (s1.generateChecks) {
                  runtimeChecks.addChecks(runtimeCheckAstNode,
                    (new Translator(s1.copy(g = g), pcs).translate(returnedChecks) match {
                      case None => sys.error("Error translating! Exiting safely.")
                      case Some(expr) => expr
                    }),
                  viper.silicon.utils.zip3(v.decider.pcs.branchConditionsSemanticAstNodes,
                    v.decider.pcs.branchConditionsAstNodes,
                    v.decider.pcs.branchConditionsOrigins).map(bc => BranchCond(bc._1, bc._2, bc._3)),
                  a,
                  s1.forFraming)
                }

                verificationResult
              }
              case _ => sys.error("This should not occur!")
            }
          case (verificationResult, None) => verificationResult
        }
      }
    }

    consumed
  }

  private def evalAndAssert(s: State, impr: Boolean, e: ast.Exp, pve: PartialVerificationError, v: Verifier)
                           (Q: (State, Term, Verifier) => VerificationResult)
                           : (VerificationResult, Option[Term]) = {

    /* It is expected that the partially consumed heap (h in the above implementation of
     * `consume`) has already been assigned to `c.partiallyConsumedHeap`.
     *
     * Switch to the eval heap (σUsed) of magic wand's exhale-ext, if necessary.
     * This is done here already (the evaluator would do it as well) to ensure that the eval
     * heap is consolidated by tryOrFail if the assertion fails.
     * The latter is also the reason for wrapping the assertion check in a tryOrFail block:
     * the tryOrFail that wraps the consumption of each top-level conjunct would not consolidate
     * the right heap.
     */

    val s1 = s.copy(h = magicWandSupporter.getEvalHeap(s),
                    reserveHeaps = Nil,
                    exhaleExt = false)

    val s2 = stateConsolidator.consolidate(s1, v)

    var returnValue: Option[(VerificationResult, Option[Term])] = None

    val result = evalpc(s2.copy(isImprecise = impr), e, pve, v)((s3, t, v1) => {
      val s4 = s3.copy(isImprecise = s2.isImprecise)
      v1.decider.assertgv(s4.isImprecise, t) {
        case true =>
          v1.decider.assume(t)
          val s5 = s4.copy(h = s.h,
                           reserveHeaps = s.reserveHeaps,
                           exhaleExt = s.exhaleExt)
          Q(s5, Unit, v1)
        case false =>
        //  println("pve " + pve + "\ne " + e + "\nv1 " + v1 + "\ns3 " + s3)
          //println("heap: " + s.h + "\noh: " + s.optimisticHeap)
          //val s4 = s3.copy(isImprecise = false)
          createFailure(pve dueTo AssertionFalse(e), v1, s3)
          // matching on the return value of assertgv
    } match {
      case (verificationResult, returnedCheck) => {
        returnValue = Some((verificationResult, returnedCheck))
        verificationResult
      }
    }})

    returnValue match {
      case Some((verificationResult, returnedCheck)) =>
        (verificationResult, returnedCheck)
      case None =>
        (result, None)
    }
  }
}
