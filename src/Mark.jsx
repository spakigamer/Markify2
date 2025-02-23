import React, { useRef, useState } from "react";
import MarkdownIt from "markdown-it";
import MdEditor from "react-markdown-editor-lite";
import "react-markdown-editor-lite/lib/index.css";
import Nav from "./Navbar/nav";
import Footer from "./Navbar/footer";
import html2pdf from "html2pdf.js";

// Markdown parser
const mdParser = new MarkdownIt({ html: true });

function Props() {
    const [content, setContent] = useState("");
    const previewRef = useRef(null);
    const [isLoading, setIsLoading] = useState(false);

    function handleEditorChange({ text }) {
        setContent(mdParser.render(text)); // Store rendered HTML
    }

    const downloadPDF = () => {
        const element = previewRef.current;
        if (!element) return;
    
        setIsLoading(true);
    
        html2pdf()
            .set({
                margin: [10, 10, 10, 10],
                filename: "markdown-preview.pdf",
                image: { type: "jpeg", quality: 1 },
                html2canvas: { 
                    scale: 2, 
                    useCORS: true,
                    scrollY: 0,
                    windowWidth: element.scrollWidth,
                    windowHeight: element.scrollHeight
                },
                jsPDF: { unit: "mm", format: "a4", orientation: "portrait" },
            })
            .from(element)
            .toPdf()
            .get('pdf')
            .then(pdf => {
                const totalPages = pdf.internal.getNumberOfPages();
                for (let i = 1; i <= totalPages; i++) {
                    pdf.setPage(i);
                    pdf.setFontSize(10);
                }
            })
            .save()
            .catch(error => {
                console.error("Error generating PDF:", error);
                alert("An error occurred while generating the PDF.");
            })
            .finally(() => setIsLoading(false));
    };

    return (
        <>
            {/* Fixed Navbar */}
            <div style={{ 
                position: "fixed",
                top: 0,
                width: "100%",
                zIndex: 1000,
                backgroundColor: "#333" // Adjust based on your navbar
            }}>
                <Nav />
            </div>

            {/* Add margin to push content down */}
            <div style={{ marginTop: "80px", padding: "20px" }}>
                <div className="flex h-screen">
                    {/* Markdown Editor */}
                    <MdEditor
                        className="w-1/2 h-full border-r"
                        style={{ height: "calc(100vh - 80px)", width: "50vw" }}
                        renderHTML={(text) => mdParser.render(text)}
                        onChange={handleEditorChange}
                        view={{ menu: true, md: true, html: false }}
                    />

                    {/* Markdown Preview */}
                    <div className="w-1/2 h-full overflow-auto p-5 border-l bg-gray-100 preview-content"
                        ref={previewRef}
                        style={{ 
                            padding: "20px", 
                            fontFamily: "Arial, sans-serif",
                            lineHeight: "1.6",
                            height: "calc(100vh - 80px)",
                            width: "50vw"
                        }}
                    >
                        <style>{`
                            /* General Styling */
.preview-content {
    font-family: "Arial", sans-serif;
    line-height: 1.6;
    color: #333;
    background: #f8f9fa; /* Light gray background */
    padding: 20px;
    border-radius: 10px;
}

/* Headings */
.preview-content h1 {
    font-size: 32px;
    font-weight: bold;
    border-bottom: 3px solid #007bff; /* Blue underline */
    padding-bottom: 5px;
    margin-bottom: 15px;
}

.preview-content h2 {
    font-size: 24px;
    font-weight: bold;
    color: #007bff; /* Primary blue */
    margin-bottom: 10px;
}

.preview-content h3 {
    font-size: 20px;
    font-weight: bold;
    color: #0056b3; /* Darker blue */
}

/* Paragraphs */
.preview-content p {
    margin-bottom: 15px;
}

/* Lists */
.preview-content ul,
.preview-content ol {
    padding-left: 20px;
    margin-bottom: 15px;
}

.preview-content ul {
    list-style-type: disc;
}

.preview-content ol {
    list-style-type: decimal;
}

/* Blockquotes */
.preview-content blockquote {
    border-left: 4px solid #007bff; /* Blue left border */
    background: #eef3f8; /* Light blue background */
    padding: 10px 15px;
    margin: 10px 0;
    font-style: italic;
    color: #555;
}

/* Code Blocks */
.preview-content pre {
    background: #2d2d2d;
    color: #ffcc00;
    padding: 10px;
    border-radius: 6px;
    overflow-x: auto;
}

.preview-content code {
    font-family: "Courier New", monospace;
    background: #f4f4f4;
    padding: 3px 6px;
    border-radius: 4px;
}

/* Tables */
.preview-content table {
    width: 100%;
    border-collapse: collapse;
    margin: 15px 0;
}

.preview-content th,
.preview-content td {
    border: 1px solid #ddd;
    padding: 10px;
    text-align: left;
}

.preview-content th {
    background-color: #007bff;
    color: #fff;
    font-weight: bold;
}

/* Horizontal Rule */
.preview-content hr {
    border: none;
    border-top: 2px solid #ccc;
    margin: 20px 0;
}

/* Buttons */
.preview-content .btn {
    display: inline-block;
    background: #007bff;
    color: #fff;
    padding: 10px 15px;
    border-radius: 5px;
    text-decoration: none;
}

.preview-content .btn:hover {
    background: #0056b3;
}

/* Checkbox (for task lists) */
.preview-content input[type="checkbox"] {
    margin-right: 8px;
    width: 16px;
    height: 16px;
    cursor: pointer;
    accent-color: #007bff;
}

                        `}</style>
                        <div dangerouslySetInnerHTML={{ __html: content }} />
                    </div>
                </div>

                {/* Download Button */}
                <button
                    onClick={downloadPDF}
                    style={{ padding: "10px", margin: "10px" }}
                    disabled={isLoading}
                    className="border cursor-pointer"
                >
                    {isLoading ? "Downloading..." : "Download as PDF"}
                </button>
            </div>

            {/* Footer */}
            <Footer />
        </>
    );
}

export default Props;
