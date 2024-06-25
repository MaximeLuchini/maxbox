import json
from fpdf import FPDF
from datetime import datetime
import os

class PDFReport(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 12)
        self.cell(0, 10, 'Rapport d\'attaque', 0, 1, 'C')

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

    def chapter_title(self, title):
        self.set_font('Arial', 'B', 12)
        self.cell(0, 10, title, 0, 1, 'L')
        self.ln(2)

    def chapter_body(self, body):
        self.set_font('Arial', '', 12)
        self.multi_cell(0, 10, body)
        self.ln()

def generate_pdf_report(report_file, username):
    with open(report_file, 'r') as file:
        report_data = json.load(file)

    pdf = PDFReport()
    pdf.add_page()
    
    pdf.set_font('Arial', 'B', 16)
    pdf.cell(0, 10, f'Rapport d\'attaque pour {username}', 0, 1, 'C')
    pdf.ln(10)

    pdf.set_font('Arial', '', 12)
    pdf.cell(0, 10, f'Date et heure: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', 0, 1, 'L')
    pdf.ln(10)

    for attack in report_data['attacks']:
        pdf.chapter_title(attack['title'])
        pdf.chapter_body(json.dumps(attack['data'], indent=4))

    output_path = os.path.join(username, f"rapport_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")
    pdf.output(output_path)

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("Usage: python report_generator.py <report_file> <username>")
        sys.exit(1)

    report_file = sys.argv[1]
    username = sys.argv[2]
    generate_pdf_report(report_file, username)
