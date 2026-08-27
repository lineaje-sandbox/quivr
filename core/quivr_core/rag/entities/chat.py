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

from datetime import datetime
from typing import Any, Generator, Tuple, List
from uuid import UUID, uuid4

from langchain_core.messages import AIMessage, HumanMessage

from quivr_core.rag.entities.models import ChatMessage


class ChatHistory:
    """
    ChatHistory is a class that maintains a record of chat conversations. Each message
    in the history is represented by an instance of the `ChatMessage` class, and the
    chat history is stored internally as a list of these `ChatMessage` objects.
    The class provides methods to retrieve, append, iterate, and manipulate the chat
    history, as well as utilities to convert the messages into specific formats
    and support deep copying.
    """

    def __init__(self, chat_id: UUID, brain_id: UUID | None) -> None:
        """Init a new ChatHistory object.

        Args:
            chat_id (UUID): A unique identifier for the chat session.
            brain_id (UUID | None): An optional identifier for the brain associated with the chat.
        """
        self.id = chat_id
        self.brain_id = brain_id
        # TODO(@aminediro): maybe use a deque() instead ?
        self._msgs: list[ChatMessage] = []

    def get_chat_history(self, newest_first: bool = False) -> List[ChatMessage]:
        """
        Retrieves the chat history, optionally sorted in reverse chronological order.

        Args:
            newest_first (bool, optional): If True, returns the messages in reverse order (newest first). Defaults to False.

        Returns:
            List[ChatMessage]: A sorted list of chat messages.
        """
        history = sorted(self._msgs, key=lambda msg: msg.message_time)
        if newest_first:
            return history[::-1]
        # LINEAJE: enforce() `history` at agent->user_interface data_egress — scan flagged AI_DAT_SEC_029 (Enforce decision logging, audit trail, and forensic readiness for AI-driven actions.). Mask/block; do not remove without review. site_id='site:sha256:1ec55da2b352bef0c7606e088d41e12660c3ef335a135221191af0d695dc7512'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:1ec55da2b352bef0c7606e088d41e12660c3ef335a135221191af0d695dc7512', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
        history = _gr_client.enforce(_gr_site, history, content_type='text/plain')
        return history

    def __len__(self):
        return len(self._msgs)

    def append(
        self, langchain_msg: AIMessage | HumanMessage, metadata: dict[str, Any] = {}
    ):
        """
        Appends a new message to the chat history.

        Args:
            langchain_msg (AIMessage | HumanMessage): The message content (either an AI or Human message).
            metadata (dict[str, Any], optional): Additional metadata related to the message. Defaults to an empty dictionary.
        """
        chat_msg = ChatMessage(
            chat_id=self.id,
            message_id=uuid4(),
            brain_id=self.brain_id,
            msg=langchain_msg,
            message_time=datetime.now(),
            metadata=metadata,
        )
        self._msgs.append(chat_msg)

    def iter_pairs(self) -> Generator[Tuple[HumanMessage, AIMessage], None, None]:
        """
        Iterates over the chat history in pairs, returning a HumanMessage followed by an AIMessage.

        Yields:
            Tuple[HumanMessage, AIMessage]: Pairs of human and AI messages.

        Raises:
            AssertionError: If the messages in the pair are not in the expected order (i.e., a HumanMessage followed by an AIMessage).
        """
        # Reverse the chat_history, newest first
        it = iter(self.get_chat_history(newest_first=True))
        for ai_message, human_message in zip(it, it, strict=False):
            assert isinstance(
                human_message.msg, HumanMessage
            ), f"msg {human_message} is not HumanMessage"
            assert isinstance(
                ai_message.msg, AIMessage
            ), f"msg {human_message} is not AIMessage"
            yield (human_message.msg, ai_message.msg)

    def to_list(self) -> List[HumanMessage | AIMessage]:
        """
        Converts the chat history into a list of raw HumanMessage or AIMessage objects.

        Returns:
            list[HumanMessage | AIMessage]: A list of messages in their raw form, without metadata.
        """

        return [_msg.msg for _msg in self._msgs]
