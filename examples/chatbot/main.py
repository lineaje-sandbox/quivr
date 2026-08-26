import os
import tempfile
from uuid import uuid4

import chainlit as cl
from langchain_community.embeddings import OllamaEmbeddings
from quivr_core import Brain, register_processor
from quivr_core.files.file import FileExtension
from quivr_core.llm import LLMEndpoint
from quivr_core.processor.implementations.simple_txt_processor import SimpleTxtProcessor
from quivr_core.rag.entities.config import LLMEndpointConfig, RetrievalConfig

# Parse .txt locally. Megaparse is the default and tries Quivr's hosted NATS,
# which fails with "nodename nor servname provided" when that host is down.
register_processor(FileExtension.txt, SimpleTxtProcessor, override=True)

# ChatOpenAI requires a key even when the backend is Ollama's OpenAI-compatible API.
os.environ.setdefault("OPENAI_API_KEY", "ollama")

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_CHAT_MODEL = os.getenv("OLLAMA_CHAT_MODEL", "llama3")
OLLAMA_EMBED_MODEL = os.getenv("OLLAMA_EMBED_MODEL", "nomic-embed-text")


def ollama_llm() -> LLMEndpoint:
    llm = LLMEndpoint.from_config(
        LLMEndpointConfig(
            model=OLLAMA_CHAT_MODEL,
            llm_api_key="ollama",
            llm_base_url=f"{OLLAMA_HOST.rstrip('/')}/v1",
            max_output_tokens=8192,
            temperature=0.7,
        )
    )
    # Local models usually cannot satisfy cited_answer tool calls.
    llm._supports_func_calling = False
    return llm


def ollama_embedder() -> OllamaEmbeddings:
    return OllamaEmbeddings(model=OLLAMA_EMBED_MODEL, base_url=OLLAMA_HOST)


@cl.on_chat_start
async def on_chat_start():
    files = None

    # Wait for the user to upload a file
    while files is None:
        files = await cl.AskFileMessage(
            content="Please upload a text .txt file to begin!",
            accept=["text/plain"],
            max_size_mb=20,
            timeout=180,
        ).send()

    file = files[0]

    msg = cl.Message(content=f"Processing `{file.name}`...")
    await msg.send()

    with open(file.path, "r", encoding="utf-8") as f:
        text = f.read()

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=file.name, delete=False
    ) as temp_file:
        temp_file.write(text)
        temp_file.flush()
        temp_file_path = temp_file.name

    brain = await Brain.afrom_files(
        name="user_brain",
        file_paths=[temp_file_path],
        llm=ollama_llm(),
        embedder=ollama_embedder(),
    )

    # Store the file path in the session
    cl.user_session.set("file_path", temp_file_path)

    # Let the user know that the system is ready
    msg.content = f"Processing `{file.name}` done. You can now ask questions!"
    await msg.update()

    cl.user_session.set("brain", brain)


@cl.on_message
async def main(message: cl.Message):
    brain = cl.user_session.get("brain")  # type: Brain
    path_config = "basic_rag_workflow.yaml"
    retrieval_config = RetrievalConfig.from_yaml(path_config)
    if brain is not None:
        # Keep the YAML workflow, but do not let it fall back to OpenAI.
        retrieval_config.llm_config = brain.llm.get_config()

    if brain is None:
        await cl.Message(content="Please upload a file first.").send()
        return

    # Prepare the message for streaming
    msg = cl.Message(content="", elements=[])
    await msg.send()

    saved_sources = set()
    saved_sources_complete = []
    elements = []

    # Use the ask_stream method for streaming responses
    async for chunk in brain.ask_streaming(
        message.content,
        run_id=uuid4(),
        retrieval_config=retrieval_config,
    ):
        await msg.stream_token(chunk.answer)
        for source in chunk.metadata.sources:
            if source.page_content not in saved_sources:
                saved_sources.add(source.page_content)
                saved_sources_complete.append(source)
                print(source)
                elements.append(cl.Text(name=source.metadata["original_file_name"], content=source.page_content, display="side"))

    
    await msg.send()
    sources = ""
    for source in saved_sources_complete:
        sources += f"- {source.metadata['original_file_name']}\n"
    msg.elements = elements
    msg.content = msg.content + f"\n\nSources:\n{sources}"
    await msg.update()
