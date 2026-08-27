# Copyright (c) Lineaje, Inc. All rights reserved.
# Lineaje UnifAI guardrail  version=2.0.0-alpha
def _lineaje_load_gr_client():
    """Lineaje-added: load gr_stub_client.py without a pip dependency."""
    import sys as _s, importlib.util as _ilu
    from pathlib import Path as _P
    n = "_lineaje_gr_stub_client"
    if n in _s.modules: return _s.modules[n]
    h = _P(__file__).resolve().parent
    _cand = next((d / "gr_stub_client.py" for d in [h, *h.parents][:8] if (d / "gr_stub_client.py").is_file()), h / "gr_stub_client.py")
    _spec = _ilu.spec_from_file_location(n, _cand)
    _s.modules[n] = _m = _ilu.module_from_spec(_spec)
    _spec.loader.exec_module(_m); return _m

import asyncio
import logging
import os
from pathlib import Path

import dotenv
from quivr_core import Brain
from quivr_core.rag.entities.config import AssistantConfig
from rich.traceback import install as rich_install

ConsoleOutputHandler = logging.StreamHandler()

logger = logging.getLogger("quivr_core")
logger.setLevel(logging.DEBUG)
# LINEAJE: enforce() `ConsoleOutputHandler` at agent->log log_emit — scan flagged AI_DAT_SEC_010 (Do not log PII.). Mask/block; do not remove without review. site_id='site:sha256:ec88ec9f4f317cbc06607eda1e80579a21aa22f41f147b6ae4fa095d8c36526b'
_gr_client = _lineaje_load_gr_client()
_gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:ec88ec9f4f317cbc06607eda1e80579a21aa22f41f147b6ae4fa095d8c36526b', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
ConsoleOutputHandler = _gr_client.enforce(_gr_site, ConsoleOutputHandler, content_type='application/json')
logger.addHandler(ConsoleOutputHandler)


logger = logging.getLogger("megaparse")
logger.setLevel(logging.DEBUG)
# LINEAJE: enforce() `ConsoleOutputHandler` at agent->log log_emit — scan flagged AI_DAT_SEC_010 (Do not log PII.). Mask/block; do not remove without review. site_id='site:sha256:679145b7533d2ce2df640a554bd5b463630e3d89aeef18ae92d1dd978add8079'
_gr_client = _lineaje_load_gr_client()
_gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:679145b7533d2ce2df640a554bd5b463630e3d89aeef18ae92d1dd978add8079', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
ConsoleOutputHandler = _gr_client.enforce(_gr_site, ConsoleOutputHandler, content_type='application/json')
logger.addHandler(ConsoleOutputHandler)


# Install rich's traceback handler to automatically format tracebacks
rich_install()


async def main():
    file_path = [
        Path("data/YamEnterprises_Monotype Fonts Plan License.US.en 04.0 (BLP).pdf")
    ]
    file_path = [
        Path(
            "data/YamEnterprises_Monotype Fonts Plan License.US.en 04.0 (BLP) reduced.pdf"
        )
    ]

    config_file_name = (
        "/Users/jchevall/Coding/quivr/backend/core/tests/rag_config_workflow.yaml"
    )

    assistant_config = AssistantConfig.from_yaml(config_file_name)
    # megaparse_config = find_nested_key(config, "megaparse_config")
    megaparse_config = assistant_config.ingestion_config.parser_config.megaparse_config
    megaparse_config.llama_parse_api_key = os.getenv("LLAMA_PARSE_API_KEY")

    processor_kwargs = {
        "megaparse_config": megaparse_config,
        "splitter_config": assistant_config.ingestion_config.parser_config.splitter_config,
    }

    brain = await Brain.afrom_files(
        name="test_brain",
        file_paths=file_path,
        processor_kwargs=processor_kwargs,
    )

    # # Check brain info
    brain.print_info()

    questions = [
        "What is the contact name for Yam Enterprises?",
        "What is the customer phone for Yam Enterprises?",
        "What is the Production Fonts (maximum) for Yam Enterprises?",
        "List the past use font software according to past use term for Yam Enterprises.",
        "How many unique Font Name are there in the Add-On Font Software Section for Yam Enterprises?",
        "What is the maximum number of Production Fonts allowed based on the license usage per term for Yam Enterprises?",
        "What is the number of production fonts licensed by Yam Enterprises? List them one by one.",
        "What is the number of Licensed Monthly Page Views for Yam Enterprises?",
        "What is the monthly licensed impressions (Digital Marketing Communications) for Yam Enterprises?",
        "What is the number of Licensed Applications for Yam Enterprises?",
        "For Yam Enterprises what is the number of applications aggregate Registered users?",
        "What is the number of licensed servers for Yam Enterprises?",
        "When is swap of Production Fonts available in Yam Enterprises?",
        "Who is the primary licensed monotype fonts user for Yam Enterprises?",
        "What is the number of Licensed Commercial Electronic Documents for Yam Enterprises?",
        "How many licensed monotype fonts users can Yam Enterprises have?",
        "How many licensed desktop users can Yam Enterprises have?",
        "Which contract type does Yam Enterprises follow?",
        "What monotype fonts support does Yam Enterprises have?",
        "Which monotype font services onboarding does Yam Enterprises have?",
        "Which Font/User Management does Yam Enterprises have?",
        "What Add-on inventory set did Yam Enterprises pick?",
        "Does Yam Enterprises have Single sign on?",
        "Is there Brand and Licence protection for Yam Enterprises?",
        "Who is the Third Party Payor's contact in Yam Enterprises?",
        "Does Yam Enterprises contract have Company Desktop License?",
        "What is the Number of Swaps Allowed for Yam Enterprises?",
        "When is swap of Production Fonts available in Yam Enterprises?",
    ]

    answers = [
        "Haruko Yamamoto",
        "81 90-1234-5603",
        "300 Production Fonts",
        "Helvetica Regular",
        "7",
        "300 Production Fonts",
        "Yam Enterprises has licensed a total of 105 Production Fonts.",
        "35,000,000",
        "2,500,000",
        "60",
        "40",
        "2",
        "Once per quarter",
        "Haruko Yamamoto",
        "0",
        "100",
        "60",
        "License",
        "Premier",
        "Premier",
        "Premier",
        "Plus",
        "Yes",
        "Yes",
        """
        Name: Yami Enterprises

        Contact: Mei Mei

        Address: 20-22 Tsuki-Tsuki-dori, Tokyo, Japan

        Phone: +81 71-9336-54023

        E-mail: mei.mei@example.com
        """,
        "Yes",
        "One (1) swap per calendar quarter",
        "The swap of Production Fonts will be available one (1) time per calendar quarter by removing Font Software as a Production Font and choosing other Font Software on the Monotype Fonts Platform.",
    ]

    retrieval_config = assistant_config.retrieval_config
    for i, (question, truth) in enumerate(zip(questions, answers, strict=False)):
        chunk = brain.ask(question=question, retrieval_config=retrieval_config)
        # LINEAJE: enforce() `question` at agent->log log_emit — scan flagged AI_DAT_SEC_010 (Do not log PII.). Mask/block; do not remove without review. site_id='site:sha256:d475d1e22867bfee41f2be2f5cf1116e8eadef2ad2efc1ea7a3071a2208716ec'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:d475d1e22867bfee41f2be2f5cf1116e8eadef2ad2efc1ea7a3071a2208716ec', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
        question = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, question, content_type='application/json'))
        print(
            "\n Question: ", question, "\n Answer: ", chunk.answer, "\n Truth: ", truth
        )
        if i == 5:
            break


if __name__ == "__main__":
    dotenv.load_dotenv()

    # Run the main function in the existing event loop
    asyncio.run(main())
