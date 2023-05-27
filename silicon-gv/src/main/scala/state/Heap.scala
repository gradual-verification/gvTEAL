// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2011-2019 ETH Zurich.

package viper.silicon.state

import viper.silicon.interfaces.state.Chunk
import viper.silicon.state.terms.Term

trait Heap {
  def values: Iterable[Chunk]
  def +(chunk: Chunk): Heap
  def +(other: Heap): Heap
  def -(chunk: Chunk): Heap
  def getChunkForValue(value: Term): Option[(Term, String)]
  def getChunksForValue(value: Term, lenient: Boolean = false): Seq[(Term, String)]
}

trait HeapFactory[H <: Heap] {
  def apply(): H
  def apply(chunks: Iterable[Chunk]): H
}

object Heap extends HeapFactory[ListBackedHeap] {
  def apply() = new ListBackedHeap(Vector.empty)
  def apply(chunks: Iterable[Chunk]) = new ListBackedHeap(chunks.toVector)
}

final class ListBackedHeap private[state] (chunks: Vector[Chunk])
    extends Heap with Immutable {

  def values = chunks

  def getChunkForValue(value: Term): Option[(Term, String)] = {
    chunks.find(chunk => {
      chunk match {
        case BasicChunk(resourceID, id, args, snap, perm) => snap == value
        case _ => sys.error(s"The chunk type ${chunk} is not supported yet!")
      }
    }) match {
      case None => None
      case Some(BasicChunk(resourceID, id, args, snap, perm)) => Some((args.head, id.toString))
    }
  }

  def getChunksForValue(value: Term, lenient: Boolean = false): Seq[(Term, String)] = {
    chunks.filter(chunk => {
      chunk match {
        case BasicChunk(resourceID, id, args, snap, perm) => {
          if (snap != value && lenient) {
            snap.toString == value.toString && snap.sort == value.sort
          } else {
            snap == value
          }
        }
        case _ => sys.error(s"The chunk type ${chunk} is not supported yet!")
      }
    }).foldLeft(Seq[(Term, String)]()) { (foundChunks, foundChunk) =>
      foundChunk match {
        case BasicChunk(resourceID, id, args, snap, perm) => foundChunks :+ (args.head, id.toString)
        case _ => foundChunks
      }
    }
  }

  def +(ch: Chunk) = new ListBackedHeap(chunks :+ ch)
  def +(h: Heap) = new ListBackedHeap(chunks ++ h.values)

  def -(ch: Chunk) = {
    val (prefix, suffix) = chunks.span(_ != ch)

    new ListBackedHeap(prefix ++ suffix.tail)
  }
}
