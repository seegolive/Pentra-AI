#!/usr/bin/env python3
"""run_lora_training.py — LoRA Fine-tuning Activation (Sprint 24)

Trains a LoRA adapter on top of qwen2.5-coder:7b using the 2,084-record
dataset from prepare_lora_training.py.

Requirements:
    pip install transformers peft trl datasets torch

Usage:
    python scripts/run_lora_training.py

Output:
    /tmp/pentra_lora/   — LoRA adapter weights
    /tmp/pentra_lora/training_summary.txt — run summary
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from datetime import datetime

# ── Config ────────────────────────────────────────────────────────────────────
JSONL_PATH   = Path("/tmp/pentra_finetune.jsonl")
OUTPUT_DIR   = Path("/tmp/pentra_lora")
BASE_MODEL   = os.getenv("LORA_BASE_MODEL", "Qwen/Qwen2.5-Coder-7B-Instruct")
MAX_RECORDS  = int(os.getenv("MAX_RECORDS", "500"))   # cap for quick run
MAX_STEPS    = int(os.getenv("MAX_STEPS", "100"))      # quick validation run
LORA_RANK    = int(os.getenv("LORA_RANK", "16"))
LORA_ALPHA   = int(os.getenv("LORA_ALPHA", "32"))
BATCH_SIZE   = int(os.getenv("BATCH_SIZE", "2"))
GRAD_ACCUM   = int(os.getenv("GRAD_ACCUM", "4"))
LR           = float(os.getenv("LEARNING_RATE", "2e-4"))
MAX_SEQ_LEN  = int(os.getenv("MAX_SEQ_LEN", "512"))

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def load_dataset_from_jsonl(path: Path, max_records: int) -> list[dict]:
    records = []
    with open(path) as f:
        for i, line in enumerate(f):
            if i >= max_records:
                break
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return records


def format_as_chat(record: dict) -> str:
    """Convert OpenAI chat format to a single training string."""
    msgs = record.get("messages", [])
    parts = []
    for msg in msgs:
        role = msg.get("role", "")
        content = msg.get("content", "")
        if role == "system":
            parts.append(f"<|im_start|>system\n{content}<|im_end|>")
        elif role == "user":
            parts.append(f"<|im_start|>user\n{content}<|im_end|>")
        elif role == "assistant":
            parts.append(f"<|im_start|>assistant\n{content}<|im_end|>")
    return "\n".join(parts)


def main():
    print("=" * 60)
    print("Pentra AI — LoRA Fine-tuning")
    print(f"Base model:  {BASE_MODEL}")
    print(f"Dataset:     {JSONL_PATH}")
    print(f"Max records: {MAX_RECORDS}")
    print(f"Max steps:   {MAX_STEPS}")
    print(f"LoRA rank:   {LORA_RANK}")
    print(f"Output:      {OUTPUT_DIR}")
    print("=" * 60)

    # ── Imports ───────────────────────────────────────────────────────────────
    import torch
    print(f"\nPyTorch: {torch.__version__}")
    print(f"CUDA: {torch.cuda.is_available()}")
    if torch.cuda.is_available():
        print(f"GPU: {torch.cuda.get_device_name(0)}")
        print(f"VRAM: {torch.cuda.get_device_properties(0).total_memory / 1024**3:.1f} GB")

    from transformers import AutoTokenizer, AutoModelForCausalLM, TrainingArguments
    from peft import LoraConfig, get_peft_model, TaskType
    from trl import SFTTrainer
    from datasets import Dataset

    # ── Load dataset ──────────────────────────────────────────────────────────
    print(f"\n📂 Loading dataset from {JSONL_PATH}...")
    if not JSONL_PATH.exists():
        print(f"❌ Dataset not found: {JSONL_PATH}")
        print("   Run: cd apps/api && uv run python ../../scripts/prepare_lora_training.py")
        sys.exit(1)

    raw = load_dataset_from_jsonl(JSONL_PATH, MAX_RECORDS)
    print(f"   Loaded {len(raw)} records")

    texts = [format_as_chat(r) for r in raw]
    dataset = Dataset.from_dict({"text": texts})
    print(f"   Dataset created: {len(dataset)} examples")

    # ── Load model & tokenizer ────────────────────────────────────────────────
    print(f"\n🤖 Loading base model: {BASE_MODEL}")
    print("   (This may take a few minutes on first run...)")

    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    model = AutoModelForCausalLM.from_pretrained(
        BASE_MODEL,
        torch_dtype=torch.bfloat16,
        device_map="auto",
        trust_remote_code=True,
    )
    model.enable_input_require_grads()
    print(f"   Model loaded on: {next(model.parameters()).device}")

    # ── LoRA config ───────────────────────────────────────────────────────────
    print(f"\n⚙️  Applying LoRA (rank={LORA_RANK}, alpha={LORA_ALPHA})...")
    lora_config = LoraConfig(
        task_type=TaskType.CAUSAL_LM,
        r=LORA_RANK,
        lora_alpha=LORA_ALPHA,
        lora_dropout=0.05,
        target_modules=["q_proj", "v_proj", "k_proj", "o_proj",
                         "gate_proj", "up_proj", "down_proj"],
        bias="none",
    )
    model = get_peft_model(model, lora_config)
    model.print_trainable_parameters()

    # ── Training args ─────────────────────────────────────────────────────────
    training_args = TrainingArguments(
        output_dir=str(OUTPUT_DIR),
        num_train_epochs=1,
        max_steps=MAX_STEPS,
        per_device_train_batch_size=BATCH_SIZE,
        gradient_accumulation_steps=GRAD_ACCUM,
        learning_rate=LR,
        lr_scheduler_type="cosine",
        warmup_steps=10,
        logging_steps=10,
        save_steps=MAX_STEPS,
        save_total_limit=1,
        fp16=False,
        bf16=torch.cuda.is_available(),
        dataloader_num_workers=0,
        report_to="none",
        optim="adamw_torch",
    )

    # ── Train ─────────────────────────────────────────────────────────────────
    print(f"\n🚀 Starting training ({MAX_STEPS} steps)...")
    start_time = datetime.now()

    # SFTTrainer v1.5+ — use formatting_func instead of dataset_text_field/packing
    def formatting_func(example):
        return example["text"]

    trainer = SFTTrainer(
        model=model,
        args=training_args,
        train_dataset=dataset,
        processing_class=tokenizer,
        formatting_func=formatting_func,
    )
    trainer.train()
    elapsed = (datetime.now() - start_time).total_seconds()

    # ── Save ──────────────────────────────────────────────────────────────────
    print(f"\n💾 Saving LoRA adapter to {OUTPUT_DIR}...")
    model.save_pretrained(str(OUTPUT_DIR))
    tokenizer.save_pretrained(str(OUTPUT_DIR))

    # ── Summary ───────────────────────────────────────────────────────────────
    summary = (
        f"Pentra AI LoRA Training Summary\n"
        f"Generated: {datetime.now().isoformat()}\n"
        f"{'='*50}\n"
        f"Base model:     {BASE_MODEL}\n"
        f"Training steps: {MAX_STEPS}\n"
        f"Dataset records: {len(raw)}\n"
        f"LoRA rank:      {LORA_RANK} / alpha: {LORA_ALPHA}\n"
        f"Elapsed:        {elapsed:.1f}s\n"
        f"Output dir:     {OUTPUT_DIR}\n"
        f"{'='*50}\n"
        f"Next steps:\n"
        f"  Convert to GGUF: python convert_hf_to_gguf.py {OUTPUT_DIR}\n"
        f"  Import to Ollama: ollama create pentra-ft -f Modelfile\n"
    )
    (OUTPUT_DIR / "training_summary.txt").write_text(summary)
    print(summary)
    print("✅ LoRA training complete!")


if __name__ == "__main__":
    main()
