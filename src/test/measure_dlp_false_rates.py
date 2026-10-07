from __future__ import annotations

import argparse
import csv
import json
import statistics
import sys
import time
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

SRC_DIR = Path(__file__).resolve().parent.parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

import dlp_llm  # noqa: E402

DEFAULT_DATASET_PATH = Path(__file__).resolve().parent / "dlp_eval_dataset.csv"

_TRUE_STRINGS = {"true", "1", "sim", "yes"}


@dataclass
class MessageResult:
    id: str
    message: str
    contains_target_pii: bool
    pii_category: str
    test_type: str
    notes: str
    repeats: list  # was_masked de cada repetição (bool), na ordem executada
    predicted_masked: bool  # voto majoritário entre as repetições
    classification: str  # "TP" | "TN" | "FP" | "FN" | "ERRO_INFRA"
    had_infra_error: bool
    mean_latency_seconds: float


def _parse_bool(value: str) -> bool:
    return value.strip().lower() in _TRUE_STRINGS


def _load_dataset(path: Path) -> list:
    with path.open(newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        raise ValueError(f"Dataset vazio ou mal formatado: {path}")
    return rows


def _classify(contains_target_pii: bool, predicted_masked: bool, had_infra_error: bool) -> str:
    if had_infra_error:
        return "ERRO_INFRA"
    if contains_target_pii and predicted_masked:
        return "TP"
    if contains_target_pii and not predicted_masked:
        return "FN"
    if not contains_target_pii and predicted_masked:
        return "FP"
    return "TN"


def _majority_vote(flags: list) -> bool:
    """Decide o rótulo final por voto majoritário entre repetições."""
    true_count = sum(1 for f in flags if f)
    return true_count >= (len(flags) / 2)


def _check_ollama_reachable(ollama_url: str, model: str, timeout: float) -> Optional[str]:
    """Faz uma chamada mínima para checar conectividade antes de gastar as
    50 mensagens do dataset. Retorna uma mensagem de erro, ou None se ok."""
    probe = dlp_llm.inspect_and_mask("teste de conectividade", ollama_url=ollama_url, model=model, timeout=timeout)
    if probe.masked_message == dlp_llm.DLP_FAILURE_TAG:
        return (
            f"Não foi possível obter uma resposta válida de {ollama_url} "
            f"(modelo '{model}'). Verifique se `ollama serve` está rodando e "
            f"se o modelo foi baixado (`ollama pull {model}`)."
        )
    return None


def run_evaluation(
    dataset_path: Path,
    *,
    repeats: int = 1,
    model: str = dlp_llm.DEFAULT_MODEL,
    ollama_url: str = dlp_llm.DEFAULT_OLLAMA_URL,
    timeout: float = dlp_llm.DEFAULT_TIMEOUT_SECONDS,
    verbose: bool = True,
    skip_connectivity_check: bool = False,
) -> dict:
    rows = _load_dataset(dataset_path)

    if not skip_connectivity_check:
        error = _check_ollama_reachable(ollama_url, model, timeout)
        if error is not None:
            print(f"❌ {error}")
            aborted_summary = _summarize([])
            aborted_summary["ollama_url"] = ollama_url
            aborted_summary["aborted"] = True
            return aborted_summary

    results: list = []

    for i, row in enumerate(rows, start=1):
        message = row["message"]
        contains_target_pii = _parse_bool(row["contains_target_pii"])

        was_masked_flags = []
        latencies = []
        had_infra_error = False

        for _ in range(repeats):
            start = time.perf_counter()
            dlp_result = dlp_llm.inspect_and_mask(
                message, ollama_url=ollama_url, model=model, timeout=timeout
            )
            elapsed = time.perf_counter() - start
            latencies.append(elapsed)

            if dlp_result.masked_message == dlp_llm.DLP_FAILURE_TAG:
                had_infra_error = True
                break

            was_masked_flags.append(dlp_result.was_masked)

        if had_infra_error:
            predicted_masked = False
            classification = "ERRO_INFRA"
        else:
            predicted_masked = _majority_vote(was_masked_flags)
            classification = _classify(contains_target_pii, predicted_masked, had_infra_error=False)

        result = MessageResult(
            id=row["id"],
            message=message,
            contains_target_pii=contains_target_pii,
            pii_category=row["pii_category"],
            test_type=row["test_type"],
            notes=row.get("notes", ""),
            repeats=was_masked_flags,
            predicted_masked=predicted_masked,
            classification=classification,
            had_infra_error=had_infra_error,
            mean_latency_seconds=statistics.fmean(latencies) if latencies else 0.0,
        )
        results.append(result)

        if verbose:
            flag = {"TP": "✅", "TN": "✅", "FP": "⚠️ FP", "FN": "🚨 FN", "ERRO_INFRA": "❌ ERRO"}[
                classification
            ]
            print(f"[{i}/{len(rows)}] {flag}  id={row['id']}  ({row['pii_category']}/{row['test_type']})")

    return _summarize(results)


def _summarize(results: list) -> dict:
    n_total = len(results)
    counts = Counter(r.classification for r in results)

    tp, tn, fp, fn = counts["TP"], counts["TN"], counts["FP"], counts["FN"]
    infra_errors = counts["ERRO_INFRA"]

    n_evaluated = n_total - infra_errors  # exclui falhas de infraestrutura do denominador
    n_positive = sum(1 for r in results if r.contains_target_pii and not r.had_infra_error)
    n_negative = sum(1 for r in results if not r.contains_target_pii and not r.had_infra_error)

    def _safe_div(numerator: int, denominator: int) -> Optional[float]:
        return (numerator / denominator) if denominator > 0 else None

    summary = {
        "n_total_mensagens": n_total,
        "n_erros_infraestrutura": infra_errors,
        "n_avaliadas": n_evaluated,
        "confusion_matrix": {"TP": tp, "TN": tn, "FP": fp, "FN": fn},
        # Definição usada na monografia: denominador = total de mensagens enviadas
        "taxa_falsos_positivos_tese": _safe_div(fp, n_total),
        "taxa_falsos_negativos_tese": _safe_div(fn, n_total),
        # Definição clássica (condicionada), para comparação/discussão
        "taxa_falsos_positivos_classica": _safe_div(fp, n_negative),
        "taxa_falsos_negativos_classica": _safe_div(fn, n_positive),
        "acuracia": _safe_div(tp + tn, n_evaluated),
        "por_categoria": _breakdown_by(results, "pii_category"),
        "por_tipo_de_teste": _breakdown_by(results, "test_type"),
        "mensagens": [asdict(r) for r in results],
    }
    return summary


def _breakdown_by(results: list, field: str) -> dict:
    breakdown = {}
    groups = {}
    for r in results:
        key = getattr(r, field)
        groups.setdefault(key, []).append(r)

    for key, group in groups.items():
        counts = Counter(r.classification for r in group)
        breakdown[key] = {
            "n": len(group),
            "TP": counts["TP"],
            "TN": counts["TN"],
            "FP": counts["FP"],
            "FN": counts["FN"],
            "ERRO_INFRA": counts["ERRO_INFRA"],
        }
    return breakdown


def _fmt_pct(value: Optional[float]) -> str:
    return f"{value:.2%}" if value is not None else "N/A"


def _print_report(summary: dict) -> None:
    print("\n" + "=" * 72)
    print("RELATÓRIO -> Taxa de Falsos Positivos e Falsos Negativos do DLP")
    print("=" * 72)
    print(f"Mensagens testadas: {summary['n_total_mensagens']}")
    if summary["n_erros_infraestrutura"]:
        print(
            f"⚠️  {summary['n_erros_infraestrutura']} mensagem(ns) falharam por erro de "
            f"infraestrutura (Ollama indisponível/resposta inválida) e foram excluídas "
            f"do cálculo das taxas. Verifique se `ollama serve` está rodando."
        )
    if summary["n_avaliadas"] == 0:
        print(
            "\n❌ Nenhuma mensagem foi avaliada com sucesso (100% de erro de "
            "infraestrutura). Confira se o Ollama está no ar em "
            f"{summary.get('ollama_url', '(url não registrada)')} antes de prosseguir."
        )
        return

    cm = summary["confusion_matrix"]
    print(f"\nMatriz de confusão: TP={cm['TP']}  TN={cm['TN']}  FP={cm['FP']}  FN={cm['FN']}")

    print("\n-- Definição usada na monografia (denominador = total de mensagens) --")
    print(f"Taxa de Falsos Positivos: {_fmt_pct(summary['taxa_falsos_positivos_tese'])}")
    print(f"Taxa de Falsos Negativos: {_fmt_pct(summary['taxa_falsos_negativos_tese'])}")

    print("\n-- Definição clássica (condicionada ao subconjunto positivo/negativo) --")
    print(f"FPR clássica (FP / benignas):  {_fmt_pct(summary['taxa_falsos_positivos_classica'])}")
    print(f"FNR clássica (FN / com PII):   {_fmt_pct(summary['taxa_falsos_negativos_classica'])}")

    print(f"\nAcurácia geral: {_fmt_pct(summary['acuracia'])}")

    print("\n-- Detalhamento por categoria de PII --")
    for category, stats in summary["por_categoria"].items():
        print(
            f"  {category:18s} n={stats['n']:<3d} TP={stats['TP']:<2d} TN={stats['TN']:<2d} "
            f"FP={stats['FP']:<2d} FN={stats['FN']:<2d}"
        )

    print("\n-- Detalhamento por tipo de teste --")
    for test_type, stats in summary["por_tipo_de_teste"].items():
        print(
            f"  {test_type:20s} n={stats['n']:<3d} TP={stats['TP']:<2d} TN={stats['TN']:<2d} "
            f"FP={stats['FP']:<2d} FN={stats['FN']:<2d}"
        )

    if cm["FN"] > 0:
        print("\n🚨 Mensagens com FALSO NEGATIVO (vazamento não detectado):")
        for m in summary["mensagens"]:
            if m["classification"] == "FN":
                print(f"   id={m['id']} [{m['pii_category']}]: {m['message']!r}")

    if cm["FP"] > 0:
        print("\n⚠️  Mensagens com FALSO POSITIVO (mascaramento indevido):")
        for m in summary["mensagens"]:
            if m["classification"] == "FP":
                print(f"   id={m['id']} [{m['test_type']}]: {m['message']!r}")


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Mede a Taxa de Falsos Positivos e Falsos Negativos do DLP "
        "(dlp_llm.inspect_and_mask) contra o dataset rotulado."
    )
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET_PATH)
    parser.add_argument(
        "--repeats",
        type=int,
        default=1,
        help="Repetições por mensagem, decididas por voto majoritário (mitiga a "
        "estocasticidade do LLM). Default: 1.",
    )
    parser.add_argument("--model", default=dlp_llm.DEFAULT_MODEL)
    parser.add_argument("--ollama-url", default=dlp_llm.DEFAULT_OLLAMA_URL)
    parser.add_argument("--timeout", type=float, default=dlp_llm.DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--output", type=Path, default=None, help="Caminho do relatório .json")
    parser.add_argument(
        "--csv-output", type=Path, default=None, help="Caminho do relatório por mensagem (.csv)"
    )
    parser.add_argument("--quiet", action="store_true", help="Não imprime o progresso mensagem a mensagem.")
    return parser


def _write_csv_report(summary: dict, path: Path) -> None:
    fieldnames = [
        "id",
        "pii_category",
        "test_type",
        "contains_target_pii",
        "predicted_masked",
        "classification",
        "mean_latency_seconds",
        "notes",
        "message",
    ]
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for m in summary["mensagens"]:
            writer.writerow({k: m[k] for k in fieldnames})


def main() -> None:
    args = _build_arg_parser().parse_args()

    summary = run_evaluation(
        args.dataset,
        repeats=args.repeats,
        model=args.model,
        ollama_url=args.ollama_url,
        timeout=args.timeout,
        verbose=not args.quiet,
    )

    _print_report(summary)

    if args.output is not None:
        args.output.write_text(json.dumps(summary, indent=2, ensure_ascii=False))
        print(f"\nRelatório JSON salvo em: {args.output}")

    if args.csv_output is not None:
        _write_csv_report(summary, args.csv_output)
        print(f"Relatório CSV por mensagem salvo em: {args.csv_output}")


if __name__ == "__main__":
    main()