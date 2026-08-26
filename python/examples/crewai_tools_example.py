"""CrewAI: `as_crewai_tools()` over the synchronous bridge.

CrewAI's `kickoff()` is synchronous, so this uses `with` rather than
`async with`. That is not a lesser path: `with` starts one private event loop in
one non-daemon thread which owns exactly one engine process for the whole crew
run, and every tool call is marshalled onto it. Opening with `async with` and
then calling `as_crewai_tools()` refuses by name rather than half-working.
"""

from __future__ import annotations

from kaleidoscope_memory import KaleidoscopeMemory


def main() -> None:
    from crewai import Agent, Crew, Task

    with KaleidoscopeMemory(profile="default", api_key="ksk_alpha....") as memory:
        agent = Agent(
            role="Memory-aware assistant",
            goal="Complete the task using only the public Kaleidoscope memory boundary",
            backstory="Uses Kaleidoscope as the sole durable memory owner.",
            llm="gpt-5-mini",
            tools=memory.as_crewai_tools(),
        )
        task = Task(
            description="What did we decide about the retry policy?",
            expected_output="A concise answer citing the remembered decision.",
            agent=agent,
        )
        print(Crew(agents=[agent], tasks=[task]).kickoff())


if __name__ == "__main__":
    main()
