import pytest
import json
from pathlib import Path
from jsonschema import validate
import re

# Get the directory of the current test file
TEST_DIR = Path(__file__).parent
PROJECT_ROOT = TEST_DIR.parent

DESIGN_MD_PATH = PROJECT_ROOT / "DESIGN.md"
PHYSICAL_MODEL_SCHEMA_PATH = PROJECT_ROOT / "src" / "equus_express" / "model" / "physical-model.schema.json"
RECIPE_MODEL_SCHEMA_PATH = PROJECT_ROOT / "src" / "equus_express" / "model" / "recipe-model.schema.json"


def load_json_schema(schema_path: Path):
    """Loads a JSON schema from a file."""
    with open(schema_path, "r") as f:
        return json.load(f)


def extract_json_blocks_from_markdown(md_path: Path):
    """Extracts all JSON code blocks from a markdown file."""
    with open(md_path, "r") as f:
        content = f.read()

    json_blocks = re.findall(r"```json\n(.*?)\n```", content, re.DOTALL)

    extracted_jsons = []
    for block in json_blocks:
        try:
            extracted_jsons.append(json.loads(block))
        except json.JSONDecodeError as e:
            pytest.fail(f"Could not parse JSON block from {md_path}: {e}\nBlock:\n{block}")
    return extracted_jsons


@pytest.fixture(scope="module")
def physical_model_schema():
    return load_json_schema(PHYSICAL_MODEL_SCHEMA_PATH)


@pytest.fixture(scope="module")
def recipe_model_schema():
    return load_json_schema(RECIPE_MODEL_SCHEMA_PATH)


@pytest.fixture(scope="module")
def design_md_json_examples():
    return extract_json_blocks_from_markdown(DESIGN_MD_PATH)


def test_physical_model_json_in_design_md(physical_model_schema, design_md_json_examples):
    """Tests the physical model JSON example in DESIGN.md against its schema."""
    if not design_md_json_examples:
        pytest.fail("No JSON examples found in DESIGN.md.")
    validate(instance=design_md_json_examples[0], schema=physical_model_schema)


def test_recipe_model_json_in_design_md(recipe_model_schema, design_md_json_examples):
    """Tests the recipe model JSON example in DESIGN.md against its schema."""
    if len(design_md_json_examples) < 2:
        pytest.fail("Not enough JSON examples found in DESIGN.md for recipe model.")
    validate(instance=design_md_json_examples[1], schema=recipe_model_schema)
