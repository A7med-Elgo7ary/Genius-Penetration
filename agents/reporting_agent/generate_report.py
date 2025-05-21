# agents/reporting_agent/generate_report.py

import asyncio
import json
import logging
import shutil
from pathlib import Path
from datetime import datetime

# Attempt to import xhtml2pdf for PDF generation
try:
    from xhtml2pdf import pisa
    XHTML2PDF_AVAILABLE = True
except ImportError:
    XHTML2PDF_AVAILABLE = False
    pisa = None

# Import from the sibling llm_interface.py file
from llm_interface import ReportingLLMInterface

# Configure logging (consistent with llm_interface.py)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("reporting_agent.log", mode='a'), # Append to the log
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("reporting_agent.generate_report")

# Define paths relative to this script's location
CURRENT_SCRIPT_PATH = Path(__file__).parent
TEMPLATES_DIR = CURRENT_SCRIPT_PATH / "templates"
REPORT_TEMPLATE_HTML = TEMPLATES_DIR / "report_template.html" # Your HTML dashboard template

# Output directory will be managed by ReportingLLMInterface, typically CURRENT_SCRIPT_PATH / "output"
# Let's get it from an instance or define it consistently
OUTPUT_DIR = CURRENT_SCRIPT_PATH / "output" 
# This should match ReportingLLMInterface's self.output_path

HTML_OUTPUT_FILENAME = "report.html"
PDF_OUTPUT_FILENAME = "report.pdf"
# JSON output filename is handled by ReportingLLMInterface ("report.json")

async def create_html_report(report_json_data: dict):
    """
    Creates the HTML report by copying the template.
    The template uses client-side JavaScript to load report.json.
    """
    if not REPORT_TEMPLATE_HTML.exists():
        logger.error(f"HTML template not found at {REPORT_TEMPLATE_HTML}")
        return

    # Ensure output directory exists (ReportingLLMInterface should also do this)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    html_output_path = OUTPUT_DIR / HTML_OUTPUT_FILENAME
    
    try:
        shutil.copy(REPORT_TEMPLATE_HTML, html_output_path)
        logger.info(f"HTML report copied to {html_output_path}")
        logger.info(f"Ensure '{HTML_OUTPUT_FILENAME}' fetches 'report.json' (not 'output/report.json') if they are in the same directory.")
    except Exception as e:
        logger.error(f"Failed to copy HTML report template: {e}")

def create_pdf_report(report_json_data: dict):
    """
    Attempts to create a PDF report from the generated JSON data.
    This is a basic implementation. For complex, JS-heavy HTML,
    a headless browser approach (Selenium, Pyppeteer) would be better.
    """
    if not XHTML2PDF_AVAILABLE:
        logger.warning("xhtml2pdf library not found. Skipping PDF generation. "
                       "Install it with: pip install xhtml2pdf")
        return

    # Ensure output directory exists
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    pdf_output_path = OUTPUT_DIR / PDF_OUTPUT_FILENAME
    
    # For xhtml2pdf to work well, it needs HTML with data already embedded.
    # The current report_template.html loads data via JavaScript, which xhtml2pdf won't execute.
    # Therefore, converting report_template.html directly will result in a PDF with "Loading..." placeholders.
    #
    # Option A: Generate a simpler HTML string here specifically for PDF conversion, embedding key data.
    # Option B: Use a server-side templating engine (like Jinja2) with a modified template for PDF.
    # Option C (Best for fidelity): Use a headless browser.
    #
    # For this example, we'll try to create a VERY basic PDF from the JSON data directly.
    # This will not look like your fancy HTML dashboard.

    executive_summary = report_json_data.get("executive_summary", "N/A")
    num_vulnerabilities = len(report_json_data.get("vulnerabilities", []))
    report_date = report_json_data.get("metadata", {}).get("report_generated", datetime.now().isoformat())

    # Create a simple HTML content string from the data
    simple_html_content = f"""
    <html>
    <head>
        <title>Penetration Test Report</title>
        <style>
            body {{ font-family: sans-serif; margin: 20px; }}
            h1 {{ color: #333; }}
            h2 {{ color: #555; border-bottom: 1px solid #eee; padding-bottom: 5px; }}
            p {{ line-height: 1.6; }}
            .summary {{ background-color: #f9f9f9; padding: 15px; border: 1px solid #ddd; }}
            .footer {{ margin-top: 30px; font-size: 0.8em; color: #777; text-align: center; }}
        </style>
    </head>
    <body>
        <h1>Penetration Test Report</h1>
        <p><strong>Report Date:</strong> {report_date}</p>
        
        <div class="summary">
            <h2>Executive Summary</h2>
            <p>{executive_summary}</p>
        </div>
        
        <h2>Vulnerability Overview</h2>
        <p>Total vulnerabilities found: {num_vulnerabilities}</p>
    """

    # Add vulnerabilities (basic list)
    if "vulnerabilities" in report_json_data and report_json_data["vulnerabilities"]:
        simple_html_content += "<h2>Vulnerabilities:</h2><ul>"
        for vuln in report_json_data["vulnerabilities"][:10]: # Display first 10 for brevity
            simple_html_content += f"<li><strong>{vuln.get('name', 'N/A')}</strong> ({vuln.get('severity', 'N/A')}): {vuln.get('description', 'N/A')[:100]}...</li>"
        simple_html_content += "</ul>"
        if len(report_json_data["vulnerabilities"]) > 10:
            simple_html_content += "<p><em>...and more. See full JSON/HTML report.</em></p>"
    
    simple_html_content += """
        <div class="footer">
            <p>This is an auto-generated PDF summary. For full details, please refer to the HTML report.</p>
        </div>
    </body>
    </html>
    """

    try:
        with open(pdf_output_path, "w+b") as result_file:
            pisa_status = pisa.CreatePDF(
                simple_html_content,  # HTML content to convert
                dest=result_file      # File handle to write PDF to
            )
        
        if not pisa_status.err:
            logger.info(f"Simplified PDF report successfully generated and saved to {pdf_output_path}")
        else:
            logger.error(f"Error generating PDF report: {pisa_status.err}")
            logger.error("The PDF generated might be incomplete or malformed.")
            logger.warning("For a high-fidelity PDF of the dynamic HTML dashboard, "
                           "consider using a headless browser (e.g., Selenium with Chrome headless + Print to PDF, or Pyppeteer).")

    except Exception as e:
        logger.error(f"Exception during PDF generation: {e}")
        logger.warning("PDF generation failed. This often happens with complex CSS or if system fonts are missing.")


async def main():
    """
    Main function to orchestrate report generation.
    """
    logger.info("Starting Reporting Agent process...")

    # Initialize the LLM interface
    # You might need to pass an API key if not set as an environment variable
    # e.g., interface = ReportingLLMInterface(api_key="YOUR_GOOGLE_API_KEY")
    try:
        llm_interface = ReportingLLMInterface() 
    except ValueError as e:
        logger.error(f"Failed to initialize ReportingLLMInterface: {e}")
        logger.error("Ensure GOOGLE_API_KEY is set or passed correctly.")
        return

    # 1. Generate the structured JSON report using the LLM
    # This method in llm_interface.py already saves 'report.json' to its output_path
    logger.info("Generating structured JSON report using LLM...")
    report_json_data = await llm_interface.generate_report()

    if not report_json_data or report_json_data.get("status") == "error":
        logger.error("Failed to generate valid report data from LLM. See llm_interface logs or error report JSON.")
        # report_json_data might contain error details which could still be useful for a basic HTML/PDF error page.
        # For simplicity, we'll try to proceed, but the reports might reflect the error.
        if not report_json_data: # If it's None or empty
             report_json_data = {
                "status": "error",
                "message": "LLM interface returned no data.",
                "executive_summary": "Report generation failed: LLM interface returned no data.",
                "metadata": {"report_generated": datetime.now().isoformat()}
            }


    # 2. Create the HTML report
    # This copies the template, which then loads report.json via client-side JS
    logger.info("Creating HTML report...")
    await create_html_report(report_json_data) # Pass data in case you want to use it for HTML later

    # 3. Create the PDF report (optional)
    logger.info("Attempting to create PDF report...")
    create_pdf_report(report_json_data)

    logger.info("Reporting Agent process completed.")
    logger.info(f"Outputs are in: {OUTPUT_DIR.resolve()}")
    logger.info(f"- JSON: {OUTPUT_DIR / 'report.json'}") # Assuming default name from llm_interface
    logger.info(f"- HTML: {OUTPUT_DIR / HTML_OUTPUT_FILENAME}")
    if XHTML2PDF_AVAILABLE and (OUTPUT_DIR / PDF_OUTPUT_FILENAME).exists():
        logger.info(f"- PDF: {OUTPUT_DIR / PDF_OUTPUT_FILENAME}")
    elif XHTML2PDF_AVAILABLE:
        logger.info(f"- PDF: Generation attempted but might have failed. Check logs.")
    else:
        logger.info(f"- PDF: Skipped (xhtml2pdf not installed).")


if __name__ == "__main__":
    # Ensure API key is handled (e.g., loaded from .env or environment)
    # from dotenv import load_dotenv
    # load_dotenv(dotenv_path=Path(__file__).resolve().parent.parent.parent / ".env") # To load from project root .env
    
    # Example: Check if GOOGLE_API_KEY is available
    import os
    if not os.getenv("GOOGLE_API_KEY"):
        logger.warning("GOOGLE_API_KEY environment variable not found. LLM calls may fail.")
        # You might want to exit or prompt the user if the key is essential and not found.

    asyncio.run(main())