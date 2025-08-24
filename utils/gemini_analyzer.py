import json
import logging
import os
from typing import Dict, Any
from google import genai
from google.genai import types
from pydantic import BaseModel

class ThreatAnalysis(BaseModel):
    classification: str
    confidence: float
    explanation: str
    recommendation: str

class GeminiThreatAnalyzer:
    """Gemini AI integration for enhanced threat analysis"""
    
    def __init__(self):
        self.client = genai.Client(api_key=os.environ.get("GEMINI_API_KEY", "demo-key"))
        
    def analyze_threat(self, scan_summary: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze threat using Gemini AI based on scan summary"""
        try:
            # Prepare system instruction
            system_prompt = """
            You are an expert cybersecurity analyst specializing in malware detection and threat assessment.
            
            Analyze the provided file scan summary and determine:
            1. classification: "Safe", "Suspicious", or "Malicious"
            2. confidence: A float between 0.0 and 1.0 indicating your confidence in the classification
            3. explanation: A detailed explanation of your reasoning
            4. recommendation: Specific actions the user should take
            
            Consider all scan results including hashes, sandbox analysis, behavioral patterns, and code analysis findings.
            Be thorough but concise in your analysis.
            
            Response format must be valid JSON with the exact keys: classification, confidence, explanation, recommendation
            """
            
            # Prepare scan data for analysis
            scan_data = f"""
            File Analysis Summary:
            - File Name: {scan_summary.get('file_name', 'unknown')}
            - File Type: {scan_summary.get('file_type', 'unknown')}
            - MD5 Hash: {scan_summary.get('hashes', {}).get('md5', 'unknown')}
            - SHA256 Hash: {scan_summary.get('hashes', {}).get('sha256', 'unknown')}
            - Sandbox Risk Level: {scan_summary.get('sandbox_risk', 'unknown')}
            - Behavior Risk Score: {scan_summary.get('behavior_score', 0)}/100
            - Code Analysis Findings: {', '.join(scan_summary.get('code_analysis_findings', []))}
            - Database Lookup Result: {scan_summary.get('lookup_result', 'unknown')}
            
            Please analyze this data and provide your threat assessment.
            """
            
            try:
                response = self.client.models.generate_content(
                    model="gemini-2.5-flash",
                    contents=[
                        types.Content(role="user", parts=[types.Part(text=scan_data)])
                    ],
                    config=types.GenerateContentConfig(
                        system_instruction=system_prompt,
                        response_mime_type="application/json",
                        response_schema=ThreatAnalysis,
                        temperature=0.1,  # Low temperature for consistent analysis
                        top_p=0.8
                    ),
                )
                
                if response.text:
                    analysis_data = json.loads(response.text)
                    
                    # Validate the response
                    analysis = ThreatAnalysis(**analysis_data)
                    
                    return {
                        'classification': analysis.classification,
                        'confidence': analysis.confidence,
                        'explanation': analysis.explanation,
                        'recommendation': analysis.recommendation,
                        'ai_model': 'gemini-2.5-flash',
                        'analysis_timestamp': scan_summary.get('timestamp', 'unknown')
                    }
                else:
                    raise ValueError("Empty response from Gemini AI")
                    
            except Exception as api_error:
                logging.error(f"Gemini AI API error: {api_error}")
                return self._fallback_analysis(scan_summary, f"AI service error: {str(api_error)}")
                
        except Exception as e:
            logging.error(f"Gemini threat analysis error: {e}")
            return self._fallback_analysis(scan_summary, str(e))
    
    def _fallback_analysis(self, scan_summary: Dict[str, Any], error_msg: str) -> Dict[str, Any]:
        """Provide fallback analysis when Gemini AI is unavailable"""
        
        # Simple rule-based fallback analysis
        behavior_score = scan_summary.get('behavior_score', 0)
        lookup_result = scan_summary.get('lookup_result', 'unknown')
        sandbox_risk = scan_summary.get('sandbox_risk', 'Low')
        
        if lookup_result == 'malicious' or behavior_score > 80 or sandbox_risk == 'High':
            classification = 'Malicious'
            confidence = 0.7
            explanation = 'High-risk indicators detected through automated scanning'
            recommendation = 'Do not execute this file. Delete immediately and run a full system scan.'
            
        elif lookup_result == 'suspicious' or behavior_score > 40 or sandbox_risk == 'Medium':
            classification = 'Suspicious'
            confidence = 0.6
            explanation = 'Multiple risk indicators present, requires manual review'
            recommendation = 'Exercise caution. Consider scanning with additional tools before use.'
            
        else:
            classification = 'Safe'
            confidence = 0.5
            explanation = 'No significant risk indicators detected in automated scans'
            recommendation = 'File appears safe based on current analysis, but remain vigilant.'
        
        return {
            'classification': classification,
            'confidence': confidence,
            'explanation': f"{explanation} (Fallback analysis: {error_msg})",
            'recommendation': recommendation,
            'ai_model': 'fallback-rules',
            'analysis_timestamp': 'unavailable'
        }
