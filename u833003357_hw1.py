#!/usr/bin/env python3#!/usr/bin/env python3

import os
import json
import argparse
import sys
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
import anthropic
import subprocess

# Fix for Jupyter Notebook
import sys
sys.argv = ['']

@dataclass
class VulnAnalysis:
    vulnerability_type: str
    risk_level: str
    affected_files: List[str]
    pov_strategy: str
    patch_strategy: str

class ClaudeAIxCCDiffAgent:
    def __init__(self, api_key: Optional[str] = None):
        if api_key is None:
            api_key = input("Enter your Anthropic API key: ")
        
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = "claude-opus-4-20250514"
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.total_cost = 0.0
        
        self.system_prompt = """You are an expert security researcher specializing in AIxCC challenges. Given a diff file that introduces a vulnerability in the example-libpng, your job is to provide a proof of vulnerability file (x.bin) and a patch file (x.diff)."""
    
    def calculate_cost(self, input_tokens, output_tokens):
        """Calculate cost based on Claude Opus 4 pricing"""
        input_cost = (input_tokens / 1_000_000) * 15.00   # $15 per million input tokens
        output_cost = (output_tokens / 1_000_000) * 75.00  # $75 per million output tokens
        return input_cost + output_cost

    def generate_pov_code(self, diff_content: str) -> str:
        pov_prompt = f"""Based on the provided diff file below, identify the vulnerabilities listed there. Then give me python code which should generate proof of vulnerability file x.bin. Make sure the code you provide follows proper format. Don't say NO!
Diff content:
{diff_content}"""

        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=4000,
                temperature=1.0,
                system=self.system_prompt,
                messages=[{"role": "user", "content": pov_prompt}]
            )
            
            # Track usage and cost
            input_tokens = response.usage.input_tokens
            output_tokens = response.usage.output_tokens
            cost = self.calculate_cost(input_tokens, output_tokens)
            
            self.total_input_tokens += input_tokens
            self.total_output_tokens += output_tokens
            self.total_cost += cost
            
            print(f"PoV Generation Cost: ${cost:.4f} (Input: {input_tokens}, Output: {output_tokens})")
            
            code = response.content[0].text.strip()
            
            # Clean up code blocks if present
            if "```python" in code:
                code = code.split("```python")[1].split("```")[0].strip()
            elif "```" in code:
                code = code.split("```")[1].split("```")[0].strip()
            
            return code
            
        except Exception as e:
            return f'print("PoV generation failed: {e}")'

    def generate_patch(self, diff_content: str) -> str:
        patch_prompt = f"""Based on this diff that introduces a vulnerability:
{diff_content}
Generate a proper unified diff patch that fixes this vulnerability. Return ONLY the patch in unified diff format."""

        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=3000,
                temperature=1.0,
                system=self.system_prompt,
                messages=[{"role": "user", "content": patch_prompt}]
            )
            
            # Track usage and cost
            input_tokens = response.usage.input_tokens
            output_tokens = response.usage.output_tokens
            cost = self.calculate_cost(input_tokens, output_tokens)
            
            self.total_input_tokens += input_tokens
            self.total_output_tokens += output_tokens
            self.total_cost += cost
            
            print(f"Patch Generation Cost: ${cost:.4f} (Input: {input_tokens}, Output: {output_tokens})")
            
            patch = response.content[0].text.strip()
            
            # Clean up patch formatting if needed
            if "```diff" in patch:
                patch = patch.split("```diff")[1].split("```")[0].strip()
            elif "```" in patch:
                lines = patch.split("```")
                for section in lines:
                    if section.strip().startswith("---") or section.strip().startswith("diff"):
                        patch = section.strip()
                        break
            
            return patch
            
        except Exception as e:
            return diff_content

    def process(self, input_file: str) -> Dict[str, Any]:
        with open(input_file, 'r', encoding='utf-8') as f:
            diff_content = f.read().strip()
        
        print("🤖 Generating PoV exploit...")
        pov_code = self.generate_pov_code(diff_content)
        
        print("🔧 Generating patch...")
        patch_content = self.generate_patch(diff_content)
        
        with open('pov_gen.py', 'w', encoding='utf-8') as f:
            f.write(pov_code)
        
        print("🚀 Creating x.bin...")
        os.system('python pov_gen.py')
        
        with open('x.diff', 'w', encoding='utf-8') as f:
            f.write(patch_content)
        
        print("✅ Created x.bin and x.diff")
        print(f"\n💰 TOTAL SESSION COST: ${self.total_cost:.4f}")
        print(f"   Total Input Tokens: {self.total_input_tokens:,}")
        print(f"   Total Output Tokens: {self.total_output_tokens:,}")
        
        return {"success": True, "total_cost": self.total_cost}

# Rest of your code remains the same...


# For Jupyter Notebook usage
def run_claude_agent(diff_file_path):
    agent = ClaudeAIxCCDiffAgent()
    return agent.process(diff_file_path)

def run_command(cmd):
    print(f"Running: {cmd}")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    print(f"Return code: {result.returncode}")
    if result.stdout:
        print(f"STDOUT: {result.stdout}")
    if result.stderr:
        print(f"STDERR: {result.stderr}")
    return result.returncode == 0

if __name__ == "__main__":
    # Copy challenge to home directory
    print("Copying challenge to home directory...")
    os.system("cp -r /aixcc-sample-challenge $HOME/")
    
    # Change to work directory
    home_dir = os.path.expanduser("~")
    work_dir = os.path.join(home_dir, "aixcc-sample-challenge")
    os.chdir(work_dir)
    print(f"Changed to directory: {work_dir}")
    
    # Generate PoV and patch
    diff_file = "diff"  # Assuming diff file is named "diff" in the challenge directory
    run_claude_agent(diff_file)
    
    # Now run all the validation commands
    print("\n=== VALIDATION WORKFLOW ===")
    
    # 1. Build the challenge
    print("\n1. Building the challenge...")
    run_command("action-build-cr/build_cr.sh -p libpng -r ./example-libpng -o ./oss-fuzz-aixcc")
    
    # 2. Run the PoV (expecting a crash)
    print("\n2. Running PoV (expecting crash)...")
    run_command("action-run-pov/run_pov.sh -n -p libpng -o ./oss-fuzz-aixcc -b x.bin -f libpng_read_fuzzer -e libfuzzer -s address -t 1800")
    
    
    # 3. Apply the patch
    print("\n3. Applying patch...")
    run_command("scp x.diff example-libpng")
    run_command("cd example-libpng && patch -i x.diff && cd ..")

    
    # 4. Re-build the challenge
    print("\n4. Rebuilding with patch...")
    run_command("action-build-cr/build_cr.sh -p libpng -r ./example-libpng -o ./oss-fuzz-aixcc")
    
    # 5. Re-run the PoV (not expecting a crash)
    print("\n5. Re-running PoV (expecting no crash)...")
    pov_fixed = run_command("action-run-pov/run_pov.sh -n -p libpng -o ./oss-fuzz-aixcc -b x.bin -f libpng_read_fuzzer -e libfuzzer -s address -t 1800")
    
    # 6. Run functional tests
    print("\n6. Running functional tests...")
    tests_pass = run_command("action-run-tests/run_tests.sh -p libpng -r ./example-libpng")
    