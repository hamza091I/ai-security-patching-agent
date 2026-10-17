import chromadb
from chromadb.utils import embedding_functions

# 1. تهيئة مسار التخزين الدائم لقاعدة بيانات المتجهات
client = chromadb.PersistentClient(path="./chroma_data")

# 2. تحديد نموذج التضمين المعتمد في المشروع
embedding_function = embedding_functions.SentenceTransformerEmbeddingFunction(
    model_name="all-MiniLM-L6-v2"
)

# 3. حذف المجموعة القديمة برمجياً لتجنب أي تعارض سابق، ثم إنشاؤها من جديد بالإعدادات الصحيحة
try:
    client.delete_collection(name="security_patches")
except Exception:
    pass

collection = client.get_or_create_collection(
    name="security_patches",
    embedding_function=embedding_function
)

def populate_knowledge_base():
    """تغذية قاعدة البيانات بنماذج الثغرات وحلول الترقيع الموصى بها"""
    patches = [
        {
            "id": "patch_eval",
            "document": (
                "Vulnerability: Arbitrary code execution via eval(). "
                "Secure Fix: Avoid eval(). Use ast.literal_eval() for safe literal parsing, "
                "or write explicit mathematical parsing logic without evaluating raw string inputs."
            ),
            "metadata": {"cwe": "CWE-95", "function": "eval", "severity": "Critical"}
        },
        {
            "id": "patch_exec",
            "document": (
                "Vulnerability: Dynamic code execution via exec(). "
                "Secure Fix: Avoid exec(). Use structured dispatch tables, dictionaries, "
                "or predefined function mappings instead of executing dynamic string blocks."
            ),
            "metadata": {"cwe": "CWE-95", "function": "exec", "severity": "Critical"}
        },
        {
            "id": "patch_system",
            "document": (
                "Vulnerability: Command injection via os.system(). "
                "Secure Fix: Replace os.system() with subprocess.run(). "
                "Set shell=False and pass arguments as a list: subprocess.run(['cmd', 'arg'], shell=False, check=True)."
            ),
            "metadata": {"cwe": "CWE-78", "function": "system", "severity": "High"}
        }
    ]

    collection.upsert(
        ids=[item["id"] for item in patches],
        documents=[item["document"] for item in patches],
        metadatas=[item["metadata"] for item in patches]
    )
    print("[+] تم تحديث وتخزين حلول الترقيع الأمني في ChromaDB بنجاح.")

def search_security_fix(query_text: str, n_results: int = 1):
    """البحث الدلالي عن أفضل ترقيع أمني مطابق لوصف الثغرة"""
    results = collection.query(
        query_texts=[query_text],
        n_results=n_results
    )
    return results

if __name__ == "__main__":
    # تغذية قاعدة البيانات
    populate_knowledge_base()

    # تجربة استرجاع ترقيع لثغرة eval
    test_vuln = "Execution of arbitrary code via eval()"
    print(f"\n--- فحص استرجاع حل للثغرة: {test_vuln} ---")
    query_result = search_security_fix(test_vuln)

    retrieved_doc = query_result["documents"][0][0]
    retrieved_meta = query_result["metadatas"][0][0]

    print(f"المعيار: {retrieved_meta['cwe']} | مستوى الخطورة: {retrieved_meta['severity']}")
    print(f"الحل المقترح المسترجع:\n{retrieved_doc}")