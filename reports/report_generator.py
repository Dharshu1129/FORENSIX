import os
import datetime
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, HRFlowable, KeepTogether
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.pdfgen import canvas

from config import Config
from database.database import db
from database.models import Case, Evidence, Artifact, TimelineEvent, Finding, ChainOfCustodyEvent, InvestigatorNote

class NumberedCanvas(canvas.Canvas):
    """Custom canvas that computes total pages and draws header/footer on each page."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748B"))
        
        # Header (Skip cover page 1)
        if self._pageNumber > 1:
            self.drawString(36, 756, "FORENSIX — DIGITAL FORENSICS EVIDENCE EXAMINATION REPORT")
            self.setStrokeColor(colors.HexColor("#CBD5E1"))
            self.setLineWidth(0.5)
            self.line(36, 750, 576, 750)
            
        # Footer
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(576, 25, page_str)
        self.drawString(36, 25, "CONFIDENTIAL & PROPRIETARY — FOR FORENSIC & LEGAL USE ONLY")
        self.setStrokeColor(colors.HexColor("#CBD5E1"))
        self.setLineWidth(0.5)
        self.line(36, 35, 576, 35)
        
        self.restoreState()

class ForensicReportGenerator:
    @staticmethod
    def generate_pdf_report(case_id):
        """
        Generates a multi-page professional PDF forensic report using ReportLab.
        Includes cover page, executive summary, hashes, chain of custody, findings, notes, conclusions, and limitations.
        Returns the file path of the generated report.
        """
        case = db.session.get(Case, case_id)
        if not case:
            raise ValueError(f"Case with ID {case_id} not found.")

        report_dir = Config.REPORT_FOLDER / case.case_number
        report_dir.mkdir(parents=True, exist_ok=True)
        
        pdf_path = report_dir / f"Forensic_Report_{case.case_number}.pdf"
        
        doc = SimpleDocTemplate(
            str(pdf_path),
            pagesize=letter,
            rightMargin=36, leftMargin=36, topMargin=45, bottomMargin=45
        )
        
        styles = getSampleStyleSheet()
        
        # Custom Forensic Palette
        c_primary = colors.HexColor('#0F172A')   # Slate 900
        c_accent = colors.HexColor('#0284C7')    # Sky 600
        c_dark = colors.HexColor('#1E293B')      # Slate 800
        c_light = colors.HexColor('#F8FAFC')     # Slate 50
        c_text = colors.HexColor('#334155')      # Slate 700
        c_critical = colors.HexColor('#EF4444')  # Red 500
        c_high = colors.HexColor('#F97316')      # Orange 500
        c_medium = colors.HexColor('#F59E0B')    # Amber 500
        c_low = colors.HexColor('#3B82F6')       # Blue 500
        
        title_style = ParagraphStyle(
            'CoverTitle',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=28,
            leading=34,
            textColor=c_primary,
            alignment=TA_CENTER
        )
        
        subtitle_style = ParagraphStyle(
            'CoverSubtitle',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=12,
            leading=16,
            textColor=c_accent,
            alignment=TA_CENTER
        )
        
        h1_style = ParagraphStyle(
            'Heading1_Custom',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=15,
            leading=19,
            textColor=c_primary,
            spaceBefore=14,
            spaceAfter=6
        )
        
        h2_style = ParagraphStyle(
            'Heading2_Custom',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=11,
            leading=15,
            textColor=c_accent,
            spaceBefore=10,
            spaceAfter=4
        )

        body_style = ParagraphStyle(
            'Body_Custom',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=9,
            leading=13,
            textColor=c_text,
            alignment=TA_JUSTIFY
        )

        table_header_style = ParagraphStyle(
            'TableHeader',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=8.5,
            leading=10.5,
            textColor=colors.white,
            alignment=TA_CENTER
        )

        table_cell_style = ParagraphStyle(
            'TableCell',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=8,
            leading=10,
            textColor=c_text
        )

        story = []

        # -------------------------------------------------------------
        # 1. COVER PAGE
        # -------------------------------------------------------------
        story.append(Spacer(1, 30))
        story.append(Paragraph("FORENSIX", title_style))
        story.append(Spacer(1, 5))
        story.append(Paragraph("DIGITAL FORENSICS EVIDENCE EXAMINATION PLATFORM", subtitle_style))
        story.append(Spacer(1, 15))
        story.append(HRFlowable(width="100%", thickness=2.5, color=c_accent, spaceBefore=10, spaceAfter=25))
        story.append(Spacer(1, 15))
        
        story.append(Paragraph("OFFICIAL EVIDENCE EXAMINATION & FINDINGS REPORT", ParagraphStyle('CenterBold', parent=title_style, fontSize=13, leading=17, textColor=c_dark)))
        story.append(Spacer(1, 20))
        
        # Cover metadata box
        gen_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        meta_data = [
            [Paragraph("<b>Case Reference:</b>", body_style), Paragraph(case.case_number, body_style)],
            [Paragraph("<b>Case Title:</b>", body_style), Paragraph(case.name, body_style)],
            [Paragraph("<b>Lead Investigator:</b>", body_style), Paragraph(case.investigator, body_style)],
            [Paragraph("<b>Investigation Status:</b>", body_style), Paragraph(case.status, body_style)],
            [Paragraph("<b>Report Generated:</b>", body_style), Paragraph(gen_time, body_style)],
            [Paragraph("<b>Total Evidence Ingested:</b>", body_style), Paragraph(str(len(case.evidence_items)), body_style)],
            [Paragraph("<b>Rule Findings Flagged:</b>", body_style), Paragraph(str(len(case.findings)), body_style)],
        ]
        
        t_meta = Table(meta_data, colWidths=[150, 370])
        t_meta.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), c_light),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
            ('PADDING', (0,0), (-1,-1), 7),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        story.append(t_meta)
        
        story.append(Spacer(1, 50))
        story.append(Paragraph("<i>CONFIDENTIAL — PREPARED FOR AUTHORIZED LEGAL AND FORENSIC PROCEEDINGS</i>", ParagraphStyle('Conf', parent=subtitle_style, fontSize=8.5, textColor=colors.gray)))
        story.append(PageBreak())

        # -------------------------------------------------------------
        # 2. EXECUTIVE SUMMARY & CASE DETAILS
        # -------------------------------------------------------------
        story.append(Paragraph("1. Executive Summary & Examination Scope", h1_style))
        story.append(HRFlowable(width="100%", thickness=1, color=c_accent, spaceBefore=2, spaceAfter=8))
        
        desc_text = case.description if case.description else "No description provided."
        story.append(Paragraph(f"<b>Case Summary:</b> {desc_text}", body_style))
        story.append(Spacer(1, 10))

        summary_text = (
            f"This digital forensics report details the technical examination performed for case <b>{case.case_number}</b>. "
            f"A total of <b>{len(case.evidence_items)}</b> digital evidence file(s) were ingested, cryptographically hashed, "
            f"and analyzed using FORENSIX. Automated rule correlation generated <b>{len(case.findings)}</b> finding(s). "
            "All evidence processing was executed strictly in a read-only environment to maintain forensic integrity."
        )
        story.append(Paragraph(summary_text, body_style))
        story.append(Spacer(1, 15))

        # -------------------------------------------------------------
        # 3. EVIDENCE SUMMARY & HASHES
        # -------------------------------------------------------------
        story.append(Paragraph("2. Digital Evidence Inventory & Cryptographic Hashes", h1_style))
        story.append(HRFlowable(width="100%", thickness=1, color=c_accent, spaceBefore=2, spaceAfter=8))
        
        if case.evidence_items:
            ev_table_data = [[
                Paragraph("EVD ID", table_header_style),
                Paragraph("Original Filename", table_header_style),
                Paragraph("Size (Bytes)", table_header_style),
                Paragraph("SHA-256 Hash", table_header_style),
                Paragraph("Integrity", table_header_style)
            ]]
            
            for ev in case.evidence_items:
                status_color = c_critical if ev.integrity_status == 'FAILED' else colors.HexColor('#16A34A')
                status_p = Paragraph(f"<font color='{status_color.hexval()}'><b>{ev.integrity_status}</b></font>", table_cell_style)
                
                ev_table_data.append([
                    Paragraph(ev.evidence_number, table_cell_style),
                    Paragraph(ev.original_filename, table_cell_style),
                    Paragraph(f"{ev.file_size:,}", table_cell_style),
                    Paragraph(f"<font size=6.5>{ev.sha256_hash}</font>", table_cell_style),
                    status_p
                ])
                
            t_ev = Table(ev_table_data, colWidths=[65, 115, 65, 210, 65])
            t_ev.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), c_primary),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
                ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, c_light]),
                ('PADDING', (0,0), (-1,-1), 6),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ]))
            story.append(t_ev)
        else:
            story.append(Paragraph("No evidence items registered for this case.", body_style))
            
        story.append(Spacer(1, 15))

        # -------------------------------------------------------------
        # 4. CHAIN OF CUSTODY
        # -------------------------------------------------------------
        story.append(Paragraph("3. Chain of Custody Audit Log", h1_style))
        story.append(HRFlowable(width="100%", thickness=1, color=c_accent, spaceBefore=2, spaceAfter=8))
        
        custody_list = ChainOfCustodyEvent.query.filter_by(case_id=case.id).order_by(ChainOfCustodyEvent.timestamp.asc()).all()
        if custody_list:
            c_data = [[
                Paragraph("Timestamp", table_header_style),
                Paragraph("Action", table_header_style),
                Paragraph("Investigator", table_header_style),
                Paragraph("Audit Details", table_header_style)
            ]]
            for c in custody_list:
                ts_str = c.timestamp.strftime("%Y-%m-%d %H:%M:%S") if c.timestamp else "N/A"
                c_data.append([
                    Paragraph(ts_str, table_cell_style),
                    Paragraph(c.event_action, table_cell_style),
                    Paragraph(c.investigator, table_cell_style),
                    Paragraph(c.description, table_cell_style)
                ])
            t_cust = Table(c_data, colWidths=[95, 110, 95, 220])
            t_cust.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), c_dark),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
                ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, c_light]),
                ('PADDING', (0,0), (-1,-1), 5),
                ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ]))
            story.append(t_cust)
        else:
            story.append(Paragraph("No chain of custody logs recorded.", body_style))

        story.append(Spacer(1, 15))

        # -------------------------------------------------------------
        # 5. SUSPICIOUS FINDINGS
        # -------------------------------------------------------------
        story.append(Paragraph("4. Rule-Based Forensic Findings", h1_style))
        story.append(HRFlowable(width="100%", thickness=1, color=c_accent, spaceBefore=2, spaceAfter=8))
        
        if case.findings:
            for fnd in case.findings:
                sev_color = c_low
                if fnd.severity == 'CRITICAL':
                    sev_color = c_critical
                elif fnd.severity == 'HIGH':
                    sev_color = c_high
                elif fnd.severity == 'MEDIUM':
                    sev_color = c_medium

                f_box = [
                    [
                        Paragraph(f"<b>[{fnd.finding_number}] {fnd.rule_name}</b>", ParagraphStyle('FHead', parent=h2_style, textColor=c_primary)),
                        Paragraph(f"<font color='{sev_color.hexval()}'><b>SEVERITY: {fnd.severity}</b></font>", ParagraphStyle('FSev', parent=body_style, alignment=TA_RIGHT))
                    ],
                    [Paragraph(f"<b>Category:</b> {fnd.category} | <b>Confidence:</b> {fnd.confidence}", body_style), ""],
                    [Paragraph(f"<b>Observed Reason:</b> {fnd.reason}", body_style), ""],
                    [Paragraph(f"<b>Technical Explanation:</b> {fnd.explanation}", body_style), ""],
                    [Paragraph(f"<b>Recommended Action:</b> {fnd.recommended_action}", body_style), ""]
                ]
                
                t_fnd = Table(f_box, colWidths=[370, 150])
                t_fnd.setStyle(TableStyle([
                    ('SPAN', (0,1), (1,1)),
                    ('SPAN', (0,2), (1,2)),
                    ('SPAN', (0,3), (1,3)),
                    ('SPAN', (0,4), (1,4)),
                    ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F1F5F9')),
                    ('BOX', (0,0), (-1,-1), 1, sev_color),
                    ('PADDING', (0,0), (-1,-1), 6),
                    ('VALIGN', (0,0), (-1,-1), 'TOP'),
                ]))
                story.append(t_fnd)
                story.append(Spacer(1, 10))
        else:
            story.append(Paragraph("No automated findings or suspicious activities flagged.", body_style))

        story.append(Spacer(1, 15))

        # -------------------------------------------------------------
        # 6. INVESTIGATOR NOTES
        # -------------------------------------------------------------
        story.append(Paragraph("5. Investigator Notes", h1_style))
        story.append(HRFlowable(width="100%", thickness=1, color=c_accent, spaceBefore=2, spaceAfter=8))
        
        notes = InvestigatorNote.query.filter_by(case_id=case.id).all()
        if notes:
            for n in notes:
                ts_str = n.timestamp.strftime("%Y-%m-%d %H:%M:%S") if n.timestamp else "N/A"
                note_p = Paragraph(f"<b>[{ts_str} - {n.investigator}]:</b> {n.note}", body_style)
                story.append(note_p)
                story.append(Spacer(1, 4))
        else:
            story.append(Paragraph("No investigator notes recorded.", body_style))

        story.append(Spacer(1, 15))

        # -------------------------------------------------------------
        # 7. FORENSIC CONCLUSION & LIMITATIONS
        # -------------------------------------------------------------
        story.append(Paragraph("6. Forensic Conclusion & Limitations", h1_style))
        story.append(HRFlowable(width="100%", thickness=1, color=c_accent, spaceBefore=2, spaceAfter=8))
        
        conclusion_text = (
            "<b>Forensic Conclusion:</b> Based strictly on the empirical evidence ingested and analyzed within FORENSIX, "
            "the observed artifacts indicate specific system events and file activity as detailed in the findings above. "
            "Cryptographic hashes verified evidence integrity during processing. All analytical conclusions are derived "
            "transparently from static file properties, browser SQLite databases, and system event logs."
        )
        story.append(Paragraph(conclusion_text, body_style))
        story.append(Spacer(1, 10))
        
        limitations_text = (
            "<b>Limitations of Examination:</b><br/>"
            "1. Analysis was performed strictly on submitted evidence copies; unallocated space and deleted file recovery were not evaluated in this pass.<br/>"
            "2. Proprietary or encrypted file formats without available credentials could not be decrypted.<br/>"
            "3. Findings represent objective evidence patterns and do not infer subjective human intent."
        )
        story.append(Paragraph(limitations_text, body_style))
        
        # Build Document with custom NumberedCanvas header/footer callback
        doc.build(story, canvasmaker=NumberedCanvas)
        
        return str(pdf_path)
