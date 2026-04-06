from .graph import build_graph


def main():
    app = build_graph()

    initial_state = {
        "project_root": "/home/jiwoo/workspace/glibc-src/glibc-2.41",
        "project": "glibc",
        "version": "glibc-2.41",
        "family": "C",
        "start_symbol": "key_call_socket",
        "current_symbol": "key_call_socket",
        "visited_symbols": ["key_call_socket"],
        "retrieved_chunks": [],
        "observations": [],
        "next_symbols": [],
        "candidate_callees": [],
        "hop_count": 0,
        "max_hops": 8,
        "status": "running",
    }

    result = app.invoke(initial_state)

    print("STATUS:", result["status"])
    print()
    print("OBSERVATIONS:")
    for x in result.get("observations", []):
        print("-", x)
    print()
    print("FINAL ANSWER:")
    print(result.get("final_answer", ""))


if __name__ == "__main__":
    main()
