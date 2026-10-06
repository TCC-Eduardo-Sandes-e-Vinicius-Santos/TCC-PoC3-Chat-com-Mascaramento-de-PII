from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent.parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from test_crypto_aes import measure_tamper_detection_rate  # noqa: E402


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Mede a Taxa de Detecção de Adulteração (Tamper Detection "
        "Rate) do AES-256-GCM implementado em crypto_aes.py."
    )
    parser.add_argument(
        "--n-trials",
        type=int,
        default=1000,
        help="Número de mensagens cifradas e adulteradas por alvo (default: 1000).",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Semente do gerador pseudoaleatório, para reprodutibilidade (default: 42).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Caminho de um arquivo .json onde salvar o relatório (opcional).",
    )
    return parser


def main() -> None:
    args = _build_arg_parser().parse_args()

    report = {
        "n_trials_per_target": args.n_trials,
        "seed": args.seed,
        "results": {},
    }

    print("=== Taxa de Detecção de Adulteração (Tamper Detection Rate) ===")
    print(f"Tentativas por alvo: {args.n_trials} | seed: {args.seed}\n")

    for target in ("ciphertext", "nonce"):
        result = measure_tamper_detection_rate(
            n_trials=args.n_trials, target=target, seed=args.seed
        )
        rate_pct = result["tamper_detection_rate"] * 100
        report["results"][target] = {
            "n_trials": result["n_trials"],
            "detected": result["detected"],
            "undetected": len(result["undetected"]),
            "unexpected_errors": len(result["unexpected_errors"]),
            "tamper_detection_rate": result["tamper_detection_rate"],
        }

        print(f"Alvo da adulteração: {target}")
        print(f"  Mensagens testadas:      {result['n_trials']}")
        print(f"  Adulterações detectadas: {result['detected']}")
        print(f"  Adulterações NÃO detectadas (falha crítica): {len(result['undetected'])}")
        print(f"  Erros inesperados (não relacionados à tag GCM): {len(result['unexpected_errors'])}")
        print(f"  Taxa de Detecção de Adulteração: {rate_pct:.2f}%\n")

    overall_detected = sum(r["detected"] for r in report["results"].values())
    overall_trials = sum(r["n_trials"] for r in report["results"].values())
    report["overall_tamper_detection_rate"] = overall_detected / overall_trials
    print(
        f"Taxa de Detecção de Adulteração (geral, ciphertext + nonce): "
        f"{report['overall_tamper_detection_rate'] * 100:.2f}%"
    )

    if args.output is not None:
        args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False))
        print(f"\nRelatório salvo em: {args.output}")


if __name__ == "__main__":
    main()