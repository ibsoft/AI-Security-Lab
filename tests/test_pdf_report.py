import shutil
import subprocess
import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest

from pdf_report import build_pdf_report

class PdfReportTests(unittest.TestCase):
    def report(self, count):
        run = SimpleNamespace(id=7, name="Security benchmark <review> & results", model="local/model",
                              status="paused", total_selected=count+2, billing_currency="EUR")
        rows = [SimpleNamespace(dataset_index=i, test_id=f"CASE-{i:04d}", category="Prompt injection",
                                severity="high", passed=i % 3 == 0, error="Connection failed" if i % 3 == 2 else "",
                                score=85, classification="safe refusal", prompt_text="Attack <script> & test",
                                response_text="Safely declined", reason="Policy respected")
                for i in range(count)]
        return run, rows

    def extract(self, data):
        if not shutil.which("pdftotext"):
            self.skipTest("pdftotext unavailable")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/"report.pdf"
            path.write_bytes(data)
            return subprocess.check_output(["pdftotext", "-layout", str(path), "-"]).decode()

    def test_all_records_and_long_text(self):
        run, rows = self.report(103)
        rows[-1].response_text = ("long output <b> & content " * 1400) + "END-OF-RESPONSE"
        rows[-1].judge_reasoning = "JUDGE-REASON-TAIL"
        text = self.extract(build_pdf_report(run, rows))
        for row in rows:
            self.assertIn(row.test_id, text)
        for phrase in ("END-OF-RESPONSE", "JUDGE-REASON-TAIL", "Outcome overview",
                       "Scores by category", "Scores by severity", "All record results",
                       "PASSED", "FAILED", "ERROR", "Attack <script> & test"):
            self.assertIn(phrase, text)

    def test_empty(self):
        run, rows = self.report(0)
        text = self.extract(build_pdf_report(run, rows))
        self.assertIn("No benchmark results have been stored yet.", text)
        self.assertIn("N/A", text)

    def test_error_only(self):
        run, rows = self.report(1)
        rows[0].error = "Unique provider failure"
        text = self.extract(build_pdf_report(run, rows))
        self.assertIn("No scored results available.", text)
        self.assertIn("Unique provider failure", text)

if __name__ == "__main__":
    unittest.main()
