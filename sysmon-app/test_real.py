import sys
sys.path.append('backend')
import server, json

try:
    print("Gathering real data...")
    m = server.get_system_metrics()
    s = server.get_security_scan()
    print("Generating real PDF...")
    pdf_bytes = server.build_pdf_report(m, s)
    with open('real_test.pdf', 'wb') as f:
        f.write(pdf_bytes)
    print("PDF SUCCESS: real_test.pdf created")
except Exception as e:
    import traceback
    traceback.print_exc()
    print(f"PDF FAILED: {e}")

try:
    print("Generating real CSV...")
    csv_data = server.build_csv_report(m, s)
    with open('real_test.csv', 'w', encoding='utf-8') as f:
        f.write(csv_data)
    print("CSV SUCCESS: real_test.csv created")
except Exception as e:
    import traceback
    traceback.print_exc()
    print(f"CSV FAILED: {e}")
