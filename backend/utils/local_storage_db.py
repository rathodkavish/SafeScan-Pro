"""
backend/utils/local_storage_db.py
Local JSON/File-Backed Database Fallback
───────────────────────────────────────
Mimics PyMongo's Database and Collection interface so that
SafeScan-Pro can persist scan history and threat statistics
locally when MongoDB Atlas is unreachable or offline.
"""

import json
import os
import threading
from datetime import datetime, timezone

DB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
DB_FILE = os.path.join(DB_DIR, "safescan_local_db.json")

_lock = threading.Lock()


class LocalCursor:
    def __init__(self, docs, projection=None):
        self.docs = [dict(d) for d in docs]
        self.projection = projection

    def sort(self, key, direction=-1):
        def _get_nested(doc, path):
            parts = path.split(".")
            val = doc
            for p in parts:
                if isinstance(val, dict):
                    val = val.get(p)
                else:
                    return ""
            return val or ""

        self.docs.sort(key=lambda d: _get_nested(d, key), reverse=(direction == -1))
        return self

    def limit(self, count):
        self.docs = self.docs[:count]
        return self

    def __iter__(self):
        for doc in self.docs:
            yield self._apply_projection(doc)

    def __len__(self):
        return len(self.docs)

    def _apply_projection(self, doc):
        if not self.projection:
            return doc
        # If projection excludes _id: {"_id": 0}
        result = dict(doc)
        if self.projection.get("_id") == 0:
            result.pop("_id", None)
        return result


class LocalCollection:
    def __init__(self, db, name):
        self.db = db
        self.name = name

    def _matches(self, doc, filter_dict):
        if not filter_dict:
            return True
        for k, v in filter_dict.items():
            if k == "$or" and isinstance(v, list):
                if not any(self._matches(doc, cond) for cond in v):
                    return False
                continue
            doc_val = doc.get(k)
            if isinstance(v, dict):
                if "$in" in v and doc_val not in v["$in"]:
                    return False
                if "$eq" in v and doc_val != v["$eq"]:
                    return False
            elif doc_val != v:
                return False
        return True

    def create_index(self, key, **kwargs):
        return key

    def count_documents(self, filter_dict=None):
        filter_dict = filter_dict or {}
        with _lock:
            docs = self.db._data.get(self.name, [])
            return sum(1 for d in docs if self._matches(d, filter_dict))

    def find_one(self, filter_dict=None):
        filter_dict = filter_dict or {}
        with _lock:
            docs = self.db._data.get(self.name, [])
            for d in docs:
                if self._matches(d, filter_dict):
                    return dict(d)
        return None

    def find(self, filter_dict=None, projection=None):
        filter_dict = filter_dict or {}
        with _lock:
            docs = self.db._data.get(self.name, [])
            matched = [dict(d) for d in docs if self._matches(d, filter_dict)]
        return LocalCursor(matched, projection)

    def insert_one(self, doc):
        new_doc = dict(doc)
        if "_id" not in new_doc:
            new_doc["_id"] = f"{self.name}_{int(datetime.now(timezone.utc).timestamp() * 1000)}"
        with _lock:
            if self.name not in self.db._data:
                self.db._data[self.name] = []
            self.db._data[self.name].append(new_doc)
            self.db._save()
        return new_doc

    def update_one(self, filter_dict, update_dict):
        with _lock:
            docs = self.db._data.get(self.name, [])
            target = None
            for d in docs:
                if self._matches(d, filter_dict):
                    target = d
                    break
            if not target:
                return None

            # Handle $set
            if "$set" in update_dict:
                for k, v in update_dict["$set"].items():
                    target[k] = v

            # Handle $inc
            if "$inc" in update_dict:
                for k, v in update_dict["$inc"].items():
                    target[k] = target.get(k, 0) + v

            # Handle $push
            if "$push" in update_dict:
                for k, v in update_dict["$push"].items():
                    if k not in target or not isinstance(target[k], list):
                        target[k] = []
                    target[k].append(v)

            self.db._save()
            return target


class LocalDatabase:
    def __init__(self, filepath=DB_FILE):
        self.filepath = filepath
        self._data = {}
        self._load()

    def _load(self):
        os.makedirs(os.path.dirname(self.filepath), exist_ok=True)
        if os.path.exists(self.filepath):
            try:
                with open(self.filepath, "r", encoding="utf-8") as f:
                    self._data = json.load(f)
            except Exception:
                self._data = {}
        else:
            self._data = {}

    def _save(self):
        try:
            with open(self.filepath, "w", encoding="utf-8") as f:
                json.dump(self._data, f, indent=2, default=str)
        except Exception as e:
            print(f"⚠️  Local database save warning: {e}")

    def __getitem__(self, name):
        return LocalCollection(self, name)


def get_local_db():
    return LocalDatabase()
