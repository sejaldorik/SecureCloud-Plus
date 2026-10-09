import pymupdf

def verify_pdf():
    pdf_path = "d:/SecureCloud+/results/IEEE_SecureCloud_Plus_Paper.pdf"
    doc = pymupdf.open(pdf_path)
    print(f"Total Pages: {len(doc)}")

    tables = ["TABLE I:", "TABLE II:", "TABLE III:", "TABLE IV:", "TABLE V:", "TABLE VI:", "TABLE VII:"]
    figures = ["Fig. 1", "Fig. 2", "Fig. 3", "Fig. 4", "Fig. 5"]
    algorithms = ["ALGORITHM 1:", "ALGORITHM 2:"]
    equations = [f"({i})" for i in range(1, 12)]
    references = [f"[{i}]" for i in range(1, 14)]

    page_texts = []
    for idx, page in enumerate(doc):
        text = page.get_text()
        page_texts.append(text)
        word_count = len(text.split())
        print(f"Page {idx+1}: {word_count} words, char count: {len(text)}")
        if word_count < 50:
            print(f"  [WARNING] Page {idx+1} seems very empty! Words: {word_count}")

    print("\n--- TABLE VERIFICATION ---")
    for t in tables:
        found_pages = [idx+1 for idx, txt in enumerate(page_texts) if t in txt]
        print(f"  {t} -> Pages: {found_pages}")
        assert len(found_pages) > 0, f"Missing table: {t}"

    print("\n--- FIGURE VERIFICATION ---")
    for f in figures:
        found_pages = [idx+1 for idx, txt in enumerate(page_texts) if f in txt]
        print(f"  {f} -> Pages: {found_pages}")
        assert len(found_pages) > 0, f"Missing figure: {f}"

    print("\n--- ALGORITHM VERIFICATION ---")
    for a in algorithms:
        found_pages = [idx+1 for idx, txt in enumerate(page_texts) if a in txt]
        print(f"  {a} -> Pages: {found_pages}")
        assert len(found_pages) > 0, f"Missing algorithm: {a}"

    print("\n--- EQUATION VERIFICATION ---")
    for eq in equations:
        found_pages = [idx+1 for idx, txt in enumerate(page_texts) if eq in txt]
        print(f"  {eq} -> Pages: {found_pages}")
        assert len(found_pages) > 0, f"Missing equation: {eq}"

    print("\n--- REFERENCE VERIFICATION ---")
    for ref in references:
        found_pages = [idx+1 for idx, txt in enumerate(page_texts) if ref in txt]
        print(f"  {ref} -> Pages: {found_pages}")
        assert len(found_pages) > 0, f"Missing reference: {ref}"

    print("\n[ALL CHECKS PASSED] Every table, figure, algorithm, equation, and reference verified in rendered PDF.")

if __name__ == "__main__":
    verify_pdf()
