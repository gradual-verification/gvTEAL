package viper.silver.ast

package object utils {

  def conjunctExps(expressions: Seq[Exp]): Exp = expressions match {
    case Seq() => TrueLit()()
    case elem +: rest => And(elem, conjunctExps(rest))()
  }
}
