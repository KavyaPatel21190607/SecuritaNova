# SecuritaNova - Advanced Antivirus Web Application

## Overview

SecuritaNova is a web-based antivirus scanner that provides comprehensive malware detection and threat analysis. The application allows users to upload files for security scanning, leveraging multiple analysis engines including AI-powered threat assessment through Google's Gemini API. It features a modern, responsive web interface with real-time scanning progress and detailed reporting capabilities.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend Architecture
- **Technology Stack**: HTML5, Tailwind CSS, vanilla JavaScript
- **Design Pattern**: Single-page application with progressive enhancement
- **UI Framework**: Tailwind CSS for responsive design with custom CSS for specific styling
- **Interactive Elements**: Canvas-based graphing system for data visualization without external chart libraries
- **File Upload**: Drag-and-drop interface with progress tracking and real-time feedback

### Backend Architecture
- **Framework**: Flask (Python) with minimal dependencies
- **Architecture Pattern**: Simple MVC structure with utility modules
- **Storage Strategy**: In-memory storage for MVP with automatic cleanup mechanisms
- **File Handling**: Temporary file storage with configurable size limits (500MB max)
- **Security Scanner**: Modular design with multiple analysis engines (hash checking, behavioral analysis, code pattern detection)

### Data Storage Solutions
- **Primary Storage**: In-memory dictionaries for scan results and file metadata
- **File Storage**: System temporary directory with automatic cleanup every 10 minutes
- **Session Management**: Flask's built-in session handling with configurable secret key
- **Data Persistence**: Stateless design suitable for containerized deployment

### Authentication and Authorization
- **Current Implementation**: Basic session management without user authentication
- **Security Features**: File type validation, size limits, and secure filename handling
- **Access Control**: No user-specific access controls in current MVP implementation

## External Dependencies

### AI Services
- **Google Gemini API**: Primary AI threat analysis engine
  - Purpose: Enhanced threat classification and risk assessment
  - Input: File metadata and scan summaries (no actual file content)
  - Output: Threat classification, confidence scores, and remediation recommendations

### Python Libraries
- **Flask**: Web framework for handling HTTP requests and responses
- **Werkzeug**: Utilities for secure filename handling and file uploads
- **python-magic**: File type detection based on content rather than extension
- **google-genai**: Official Google Generative AI client library
- **Pydantic**: Data validation and parsing for AI response handling

### Frontend Libraries
- **Tailwind CSS**: Utility-first CSS framework for responsive design
- **Feather Icons**: Lightweight icon library for UI elements

### System Dependencies
- **File Type Detection**: Uses python-magic library for MIME type identification
- **Temporary File Management**: Built on Python's tempfile module for secure file handling
- **Logging**: Python's built-in logging module for debugging and monitoring

### Configuration Requirements
- **Environment Variables**: 
  - `GEMINI_API_KEY`: Required for AI threat analysis
  - `SESSION_SECRET`: Flask session security (defaults to development key)
- **File System**: Requires write access to system temporary directory
- **Network**: Outbound HTTPS access for Gemini API communication