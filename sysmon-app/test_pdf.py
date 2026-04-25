from fpdf import FPDF
import os

pdf = FPDF()
pdf.add_page()
pdf.set_font("Helvetica", size=12)
try:
    # This character (u2022 bullet or u2013 en-dash) often crashes Helvetica in fpdf
    pdf.cell(200, 10, txt="Special char: \u2013") 
    print("Success")
except Exception as e:
    print(f"Error: {e}")
