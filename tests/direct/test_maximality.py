import itertools
import random
import pytest
from tests.evidence import material, canonical


def matrix_for(ids, labels):
    edges = list(itertools.combinations(ids, 2))
    matrix = {}
    for (a, b), label in zip(edges, labels):
        value = material(label, a, b)
        if label == "SHARED_ORIGIN":
            # Different explicit shared edges use one common production origin.
            value["left_origin_ids"] = value["right_origin_ids"] = ["common"]
        matrix[a + "|" + b] = value
    return matrix


def reference_clique(ids, matrix):
    # Independent specification using combinations, not the implementation's masks.
    for size in range(len(ids), -1, -1):
        for candidate in itertools.combinations(ids, size):
            if all(matrix[a + "|" + b]["relation"] == "INDEPENDENT" for a, b in itertools.combinations(candidate, 2)):
                return list(candidate)


def test_all_32768_six_source_independence_graphs(module):
    ids = ["a", "b", "c", "d", "e", "f"]
    # Every binary graph on six sources, each checked against an independent
    # reference. The contract visits all 64 subsets for each graph.
    for mask in range(1 << 15):
        matrix = matrix_for(ids, ["INDEPENDENT" if mask & (1 << i) else "UNKNOWN" for i in range(15)])
        assert module.maximal_subset(ids, matrix) == reference_clique(ids, matrix)


def test_every_three_source_ternary_matrix(module):
    ids = ["a", "b", "c"]
    for labels in itertools.product(("INDEPENDENT", "SHARED_ORIGIN", "UNKNOWN"), repeat=3):
        matrix = matrix_for(ids, labels)
        assert module.maximal_subset(ids, matrix) == reference_clique(ids, matrix)


def test_shared_transitive_closure_cannot_contradict_independent(module):
    ids = ["a", "b", "c"]
    matrix = matrix_for(ids, ["SHARED_ORIGIN", "INDEPENDENT", "SHARED_ORIGIN"])
    assert module.matrix_analysis(ids, matrix)["contradiction"]


def test_unknown_cross_cluster_blocks_conclusive_count(module):
    ids = ["a", "b", "c"]
    matrix = matrix_for(ids, ["INDEPENDENT", "UNKNOWN", "INDEPENDENT"])
    result = module.matrix_analysis(ids, matrix)
    assert result["unknown_cross_cluster"]
    assert result["diagnostic_subset"] == ["a", "b"]


def test_unknown_inside_known_shared_cluster_does_not_inflate(module):
    ids = ["a", "b", "c"]
    matrix = matrix_for(ids, ["SHARED_ORIGIN", "UNKNOWN", "SHARED_ORIGIN"])
    result = module.matrix_analysis(ids, matrix)
    assert not result["unknown_cross_cluster"]
    assert result["diagnostic_subset"] == ["a"]


def test_origin_overlap_contradiction_across_other_pair(module):
    ids = ["a", "b", "c"]
    matrix = matrix_for(ids, ["INDEPENDENT"] * 3)
    matrix["a|c"]["left_origin_ids"] = ["b-origin"]
    assert module.matrix_analysis(ids, matrix)["contradiction"]


def test_full_six_source_contract_matrix_persisted(rhizome, prepare, module):
    ids = ("a", "b", "c", "d", "e", "f")
    prepare(names=ids, count=3)
    for key, decision in matrix_for(list(ids), ["INDEPENDENT"] * 15).items():
        decision.update({"available": True, "unresolved_reason": "", "witnesses": [], "pair_ids": key.split("|")})
        rhizome.pairs["batch-1:" + key] = canonical(decision)
    result = rhizome.seal_batch("batch-1")["sealed_result"]
    assert result["certified_origin_count"] == 6 and result["certified_subset"] == list(ids)
    assert len(result["relation_matrix"]) == 15 and result["coverage_complete"]
