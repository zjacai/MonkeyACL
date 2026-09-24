import os
import runpy


if __name__ == "__main__":
    target = os.path.join(os.path.dirname(os.path.abspath(__file__)), "monkeyACL.py")
    runpy.run_path(target, run_name="__main__")
