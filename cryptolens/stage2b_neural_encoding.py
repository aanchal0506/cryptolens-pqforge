"""Stage 2b - Neural code encoding.

Both encoders turn code text into a dense vector, so the next stage does not care
which one produced it.

  CodeBertEncoder   the encoder named in the project brief. Needs torch + transformers
                    and the model weights (downloaded from HuggingFace, or a folder
                    produced by train_codebert.py).
  TfidfSvdEncoder   an offline stand-in: identifier TF-IDF compressed with SVD. It has no
                    pre-training, so it will not match CodeBERT, but it lets the whole
                    pipeline run on a laptop without a GPU or internet.

The encoder is chosen by name through build_encoder().
"""
import re
from abc import ABC, abstractmethod

import numpy as np


def split_identifiers(text):
    """Break code into lower-case word pieces: 'generateKey_pair' -> generate key pair."""
    words = re.findall(r"[A-Za-z][A-Za-z0-9]*|\d+", text)
    pieces = []
    for w in words:
        # split camelCase and keep digits as their own tokens
        pieces += [p.lower() for p in re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+", w)]
    return " ".join(pieces)


class CodeEncoder(ABC):
    """Common interface: fit on training text, then transform any text to vectors."""

    name = "base"

    @abstractmethod
    def fit(self, texts):
        ...

    @abstractmethod
    def transform(self, texts):
        ...

    @property
    @abstractmethod
    def dim(self):
        ...


class TfidfSvdEncoder(CodeEncoder):
    name = "tfidf-svd"

    def __init__(self, n_components=96):
        from sklearn.decomposition import TruncatedSVD
        from sklearn.feature_extraction.text import TfidfVectorizer
        self._vectorizer = TfidfVectorizer(preprocessor=split_identifiers, ngram_range=(1, 2),
                                           min_df=2, sublinear_tf=True, max_features=20000)
        self._svd_cls = TruncatedSVD
        self._n_components = n_components
        self._svd = None

    def fit(self, texts):
        matrix = self._vectorizer.fit_transform(texts)
        # SVD cannot use more components than the matrix has columns
        k = max(2, min(self._n_components, matrix.shape[1] - 1, matrix.shape[0] - 1))
        self._svd = self._svd_cls(n_components=k, random_state=42).fit(matrix)
        return self

    def transform(self, texts):
        return self._svd.transform(self._vectorizer.transform(texts)).astype(np.float32)

    @property
    def dim(self):
        return self._svd.n_components


class CodeBertEncoder(CodeEncoder):
    """[CLS] embedding from CodeBERT (768 values per snippet).

    `model_path` can be 'microsoft/codebert-base' or a folder saved by train_codebert.py.
    Weights are loaded lazily, so importing this file never needs torch.
    """

    name = "codebert"

    def __init__(self, model_path="microsoft/codebert-base", max_length=512, batch_size=16):
        self.model_path = model_path
        self.max_length = max_length
        self.batch_size = batch_size
        self._tokenizer = None
        self._model = None

    def _load(self):
        if self._model is None:
            import torch
            from transformers import AutoModel, AutoTokenizer
            self._torch = torch
            self._tokenizer = AutoTokenizer.from_pretrained(self.model_path)
            self._model = AutoModel.from_pretrained(self.model_path).eval()

    def fit(self, texts):
        # Nothing to learn here: fine-tuning is done separately in train_codebert.py.
        self._load()
        return self

    def transform(self, texts):
        self._load()
        chunks = []
        with self._torch.no_grad():
            for i in range(0, len(texts), self.batch_size):
                batch = self._tokenizer(list(texts[i:i + self.batch_size]), padding=True,
                                        truncation=True, max_length=self.max_length,
                                        return_tensors="pt")
                cls = self._model(**batch).last_hidden_state[:, 0, :]
                chunks.append(cls.numpy())
        return np.vstack(chunks).astype(np.float32)

    @property
    def dim(self):
        return 768

    # The model itself is not pickled; only its path is kept and it is reloaded on demand.
    def __getstate__(self):
        state = self.__dict__.copy()
        state["_model"] = None
        state["_tokenizer"] = None
        state.pop("_torch", None)
        return state


def build_encoder(kind="tfidf", **kwargs):
    """Factory used by training and by the saved model."""
    if kind == "codebert":
        return CodeBertEncoder(**kwargs)
    if kind == "tfidf":
        return TfidfSvdEncoder(**kwargs)
    raise ValueError(f"unknown encoder {kind!r} (use 'tfidf' or 'codebert')")