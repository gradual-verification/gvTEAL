package viper.silicon.rules

import viper.silver.ast
import viper.silver.verifier.PartialVerificationError
import viper.silicon.interfaces.VerificationResult
import viper.silicon.state.State
import viper.silicon.state.terms._
import viper.silicon.verifier.Verifier
import viper.silicon.{WellformednessRecord, SymbExLogger}



trait WellFormednessRules extends SymbolicExecutionRules {
  def wellformed(s: State,
                 sf: (Sort, Verifier) => Term,
                 e: Seq[ast.Exp],
                 pve: PartialVerificationError,
                 v: Verifier)
                (Q: (State, Verifier) => VerificationResult)
                : VerificationResult
}

object wellFormedness extends WellFormednessRules with Immutable {
  import producer._

  def wellformed(s: State,
                 sf: (Sort, Verifier) => Term,
                 e: Seq[ast.Exp],
                 pve: PartialVerificationError,
                 v: Verifier)
                (Q: (State, Verifier) => VerificationResult)
                : VerificationResult = {

    val sepIdentifier = SymbExLogger.currentLog().insert(new WellformednessRecord(viper.silicon.utils.ast.BigAnd(e), s, v.decider.pcs))
    produce(s, sf, viper.silicon.utils.ast.BigAnd(e), pve, v)((s1, v1) =>
      produce(s, sf, viper.silicon.utils.ast.BigAnd(e), pve, v1)((s2, v2) => {
        SymbExLogger.currentLog().collapse( viper.silicon.utils.ast.BigAnd(e), sepIdentifier) //TODO: fix type mismatch
        Q(s2, v2)}))
  }
}
