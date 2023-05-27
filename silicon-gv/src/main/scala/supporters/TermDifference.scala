package viper.silicon.supporters

import viper.silicon.state.terms
import viper.silicon.state.profilingInfo
import viper.silicon.decider.Decider
import viper.silicon.verifier.Verifier

object TermDifference {

  def visitor(expansionPhase: terms.Term => terms.Term, excludedTerms: Seq[String], term: terms.Term): terms.Term = term match {
    case terms.Null() if excludedTerms.contains("Null") => expansionPhase(term)
    case terms.Null() => term
    case terms.False() if excludedTerms.contains("False") => expansionPhase(term)
    case terms.False() => term
    case terms.True() if excludedTerms.contains("True") => expansionPhase(term)
    case terms.True() => term
    case terms.IntLiteral(_) if excludedTerms.contains("IntLiteral") => expansionPhase(term)
    case terms.IntLiteral(i) => term
    case terms.Unit if excludedTerms.contains("Unit") => expansionPhase(term)
    case terms.Unit => term
    case terms.First(_) if excludedTerms.contains("First") => expansionPhase(term)
    case terms.First(t) => terms.First(visitor(expansionPhase, excludedTerms, t))
    case terms.Second(_) if excludedTerms.contains("Second") => expansionPhase(term)
    case terms.Second(t) => terms.Second(visitor(expansionPhase, excludedTerms, t))
    case terms.Combine(_, _) if excludedTerms.contains("Combine") => expansionPhase(term)
    case terms.Combine(t0, t1) => terms.Combine(visitor(expansionPhase, excludedTerms, t0), visitor(expansionPhase, excludedTerms, t1))
    case terms.Plus(_, _) if excludedTerms.contains("Plus") => expansionPhase(term)
    case terms.Plus(t0, t1) => terms.Plus(visitor(expansionPhase, excludedTerms, t0), visitor(expansionPhase, excludedTerms, t1))
    case terms.Minus(_, _) if excludedTerms.contains("Minus") => expansionPhase(term)
    case terms.Minus(t0, t1) => terms.Minus(visitor(expansionPhase, excludedTerms, t0), visitor(expansionPhase, excludedTerms, t1))
    case terms.Div(_, _) if excludedTerms.contains("Div") => expansionPhase(term)
    case terms.Div(t0, t1) => terms.Div(visitor(expansionPhase, excludedTerms, t0), visitor(expansionPhase, excludedTerms, t1))
    case terms.Times(_, _) if excludedTerms.contains("Times") => expansionPhase(term)
    case terms.Times(t0, t1) => terms.Times(visitor(expansionPhase, excludedTerms, t0), visitor(expansionPhase, excludedTerms, t1))
    case terms.Mod(_, _) if excludedTerms.contains("Mod") => expansionPhase(term)
    case terms.Mod(t0, t1) => terms.Mod(visitor(expansionPhase, excludedTerms, t0), visitor(expansionPhase, excludedTerms, t1))
    case terms.Not(_) if excludedTerms.contains("Not") => expansionPhase(term)
    case terms.Not(t) => terms.Not(visitor(expansionPhase, excludedTerms, t))
    case terms.Or(_) if excludedTerms.contains("Or") => expansionPhase(term)
    case terms.Or(ts) => terms.Or(ts.map(term => visitor(expansionPhase, excludedTerms, term)))
    case terms.And(_) if excludedTerms.contains("And") => expansionPhase(term)
    case terms.And(ts) => terms.And(ts.map(term => visitor(expansionPhase, excludedTerms, term)))
    case terms.Implies(_, _) if excludedTerms.contains("Implies") => expansionPhase(term)
    case terms.Implies(t0, t1) => terms.Implies(visitor(expansionPhase, excludedTerms, t0), visitor(expansionPhase, excludedTerms, t1))
    case terms.Iff(_, _) if excludedTerms.contains("Iff") => expansionPhase(term)
    case terms.Iff(t0, t1) => terms.Iff(visitor(expansionPhase, excludedTerms, t0), visitor(expansionPhase, excludedTerms, t1))
    case terms.Equals(_, _) if excludedTerms.contains("Equals") => expansionPhase(term)
    case terms.Equals(t0, t1) => terms.Equals(visitor(expansionPhase, excludedTerms, t0), visitor(expansionPhase, excludedTerms, t1))
    case terms.Less(_, _) if excludedTerms.contains("Less") => expansionPhase(term)
    case terms.Less(t0, t1) => terms.Less(visitor(expansionPhase, excludedTerms, t0), visitor(expansionPhase, excludedTerms, t1))
    case terms.AtMost(_, _) if excludedTerms.contains("AtMost") => expansionPhase(term)
    case terms.AtMost(t0, t1) => terms.AtMost(visitor(expansionPhase, excludedTerms, t0), visitor(expansionPhase, excludedTerms, t1))
    case terms.AtLeast(_, _) if excludedTerms.contains("AtLeast") => expansionPhase(term)
    case terms.AtLeast(t0, t1) => terms.AtLeast(visitor(expansionPhase, excludedTerms, t0), visitor(expansionPhase, excludedTerms, t1))
    case terms.Greater(_, _) if excludedTerms.contains("Greater") => expansionPhase(term)
    case terms.Greater(t0, t1) => terms.Greater(visitor(expansionPhase, excludedTerms, t0), visitor(expansionPhase, excludedTerms, t1))
    case terms.Ite(_, _, _) if excludedTerms.contains("Ite") => expansionPhase(term)
    case terms.Ite(t0, t1, t2) => terms.Ite(visitor(expansionPhase, excludedTerms, t0), visitor(expansionPhase, excludedTerms, t1), visitor(expansionPhase, excludedTerms, t2))
    case terms.Var(_, _) if excludedTerms.contains("Var") => expansionPhase(term)
    case terms.Var(name, sort) => terms.Var(name, sort)
    case terms.SortWrapper(_, _) if excludedTerms.contains("SortWrapper") => expansionPhase(term)
    case terms.SortWrapper(t, sort) => terms.SortWrapper(visitor(expansionPhase, excludedTerms, t), sort)
  }

  def eliminateImplications(symbolicValue: terms.Term): terms.Term = symbolicValue match {
    case terms.Implies(t0, t1) =>
      terms.Or(Seq(
        visitor(eliminateImplications, Seq("Implies", "Iff"), terms.Not(t0)),
        visitor(eliminateImplications, Seq("Implies", "Iff"), t1)))
    case terms.Iff(t0, t1) =>
      terms.And(Seq(
        terms.Or(Seq(
          visitor(eliminateImplications, Seq("Implies", "Iff"), terms.Not(t0)),
          visitor(eliminateImplications, Seq("Implies", "Iff"), t1))),
        terms.Or(Seq(
          visitor(eliminateImplications, Seq("Implies", "Iff"), t0),
          visitor(eliminateImplications, Seq("Implies", "Iff"), terms.Not(t1))))))
    case _ => visitor(eliminateImplications, Seq("Implies", "Iff"), symbolicValue)
  }

  def pushNegations(symbolicValue: terms.Term): terms.Term = symbolicValue match {
    case terms.Not(terms.And(ts)) => terms.Or(ts.map(term => pushNegations(terms.Not(term))))
    case terms.Not(terms.Or(ts)) => terms.And(ts.map(term => pushNegations(terms.Not(term))))
    case terms.Not(t) => terms.Not(visitor(pushNegations, Seq("Not"), t))
    case _ => visitor(pushNegations, Seq("Not"), symbolicValue)
  }

  def eliminateNestedOrs(symbolicValue: terms.Term): terms.Term = symbolicValue match {
    case terms.Or(_) => terms.Or(returnOrBodies(symbolicValue))
    case _ => visitor(eliminateNestedOrs, Seq("Or"), symbolicValue)
  }

  def returnOrBodies(symbolicValue: terms.Term): Seq[terms.Term] = symbolicValue match {
    case terms.Or(ts) => ts.foldRight(Seq[terms.Term]())((term, restTerms) =>
        term match {
          case terms.Or(vs) => returnOrBodies(terms.Or(vs)) ++: restTerms
          case _ => visitor(eliminateNestedOrs, Seq("Or"), term) +: restTerms
        })
  }

  // this must get called when an or is encountered, possibly or probably
  def pullAnds(symbolicValue: terms.Term): terms.Term = eliminateNestedOrs(symbolicValue) match {
    case terms.Or(ts) => 
      ts.find(term => term match {
        case terms.And(_) => true
        case _ => false
      }) match {
        case None => terms.Or(ts.map(term => visitor(pullAnds, Seq("Or"), term)))
        // this branch must be taken when that or term contains an and term, maybe
        case Some(t) => expandAnds(t, ts.filterNot(term => term == t))
      }
    case t => visitor(pullAnds, Seq("Or"), t)
  }

  def expandAnds(andTerm: terms.Term, orContents: Seq[terms.Term]): terms.Term = andTerm match {
    case terms.And(ts) => terms.And(ts.map(term => pullAnds(terms.Or(term +: ts))))
  }

  def eliminateNestedAnds(symbolicValue: terms.Term): terms.Term = symbolicValue match {
    case terms.And(_) => terms.And(returnAndBodies(symbolicValue))
    case _ => visitor(eliminateNestedAnds, Seq("And"), symbolicValue)
  }

  def returnAndBodies(symbolicValue: terms.Term): Seq[terms.Term] = symbolicValue match {
    case terms.And(ts) => ts.foldRight(Seq[terms.Term]())((term, restTerms) =>
        term match {
          case terms.And(_) => returnAndBodies(term) ++: restTerms
          case _ => visitor(eliminateNestedAnds, Seq("And"), term) +: restTerms
        })
  }

  def expandConjuncts(symbolicValue: terms.Term): Seq[terms.Term] = {
    eliminateNestedAnds(pullAnds(pushNegations(eliminateImplications(symbolicValue)))).topLevelConjuncts
  }

  def reduceConjuncts(symbolicValueConjuncts: Seq[terms.Term]): terms.Term = {
    terms.And(symbolicValueConjuncts)
  }

  // testing transform
  val makeVar: String => terms.Var = (varName: String) => terms.Var(viper.silicon.state.Identifier(varName), terms.sorts.Int)

  val simpleImplicationTerm = terms.Implies(makeVar("x"), makeVar("y"))

  val simpleNegationTerm = terms.Not(makeVar("x"))

  val moreComplexNegationTerm = terms.Not(simpleImplicationTerm)

  // 3
  val moreComplexImplicationTerm = terms.Iff(terms.Implies(makeVar("a"), makeVar("e")), moreComplexNegationTerm)

  val evenMoreComplexNegationTerm = terms.Not(moreComplexNegationTerm)

  val evenMoreComplexNegationTermForRealThisTime = terms.Not(moreComplexImplicationTerm)

  // 10
  val termWithIgnoredTerms =
    terms.Iff(
      terms.Plus(terms.Var(viper.silicon.state.Identifier("k"), terms.sorts.Int), makeVar("w")),
      terms.Not(terms.Implies(
        terms.Plus(
          terms.Not(moreComplexImplicationTerm),
          terms.Not(evenMoreComplexNegationTermForRealThisTime)),
        terms.Not(evenMoreComplexNegationTerm))))

  // 24
  val moreComplexTermWithIgnoredTerms = terms.Implies(terms.Plus(termWithIgnoredTerms, evenMoreComplexNegationTermForRealThisTime), termWithIgnoredTerms)

  def testCNFTransform(): Unit = {

    println(pushNegations(eliminateImplications(simpleImplicationTerm)))

    println(pushNegations(eliminateImplications(simpleNegationTerm)))

    println(pushNegations(eliminateImplications(moreComplexNegationTerm)))

    println(pushNegations(eliminateImplications(moreComplexImplicationTerm)))

    println(pushNegations(eliminateImplications(evenMoreComplexNegationTerm)))

    println(pushNegations(eliminateImplications(evenMoreComplexNegationTermForRealThisTime)))

    println(pushNegations(eliminateImplications(termWithIgnoredTerms)))

    println(pullAnds(pushNegations(eliminateImplications(evenMoreComplexNegationTermForRealThisTime))))

    println(pullAnds(pushNegations(eliminateImplications(termWithIgnoredTerms))))

    println(eliminateNestedAnds(pullAnds(pushNegations(eliminateImplications(termWithIgnoredTerms)))))

    println(moreComplexTermWithIgnoredTerms)

    println(pushNegations(eliminateImplications(moreComplexTermWithIgnoredTerms)))

    println(eliminateNestedAnds(pullAnds(pushNegations(eliminateImplications(moreComplexTermWithIgnoredTerms)))))

    println(eliminateNestedAnds(eliminateNestedAnds(pullAnds(pushNegations(eliminateImplications(moreComplexTermWithIgnoredTerms))))))
  }

  // we'll need to add profiling here; every time a conjunct is eliminated, we
  // should record (or take note of) it
  def termDifference(solver: Decider, symbolicValue: terms.Term, asserting: Boolean = false): terms.Term = {

    val timeout = Verifier.config.checkTimeout.toOption match {
      case None => 1000
      case Some(verifierTimeoutValue) => verifierTimeoutValue
    }

    // we (hopefully) have a conjunct elimination site here
    reduceConjuncts(
      expandConjuncts(symbolicValue).foldRight(Seq[terms.Term]())((term, terms) => {
      if (solver.check(term, timeout)) {

        if (asserting) {
          profilingInfo.incrementEliminatedConjuncts
        }

        terms
      } else {
        term +: terms
      }
    }))

    // var symbolicValueConjuncts = expandConjuncts(symbolicValue)
    
    // for (term <- symbolicValueConjuncts) {
    //   if (solver.check(term, 1000)) {
    //     symbolicValueConjuncts = symbolicValueConjuncts
    //       .filterNot(possibleRedundantTerm => possibleRedundantTerm == term)
    //   }
    // }

    // reduceConjuncts(symbolicValueConjuncts)
  }
}
