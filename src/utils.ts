export function isAlgorithm<T extends Algorithm>(algorithm: Algorithm, name: string): algorithm is T {
  return algorithm.name.toUpperCase() === name.toUpperCase() ;
}
