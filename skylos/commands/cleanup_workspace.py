"""Explicit CLI actions for local plans and cited advisory review records."""

from __future__ import annotations


def add_workspace_arguments(parser):
    parser.add_argument(
        "--plans", action="store_true", help="List local ordered plans."
    )
    parser.add_argument("--plan", metavar="NAME", help="View a local ordered plan.")
    parser.add_argument(
        "--create-plan", metavar="NAME", help="Create an ordered local plan."
    )
    parser.add_argument(
        "--plan-task",
        action="append",
        default=[],
        metavar="ID",
        help="Select a task for --create-plan; repeat in the desired order.",
    )
    parser.add_argument(
        "--prerequisite",
        action="append",
        default=[],
        metavar="TEXT",
        help="Record a plan prerequisite as text; never executed.",
    )
    parser.add_argument(
        "--acceptance-check",
        action="append",
        default=[],
        metavar="TEXT",
        help="Record a plan acceptance check as text; never executed.",
    )
    parser.add_argument("--move-task", metavar="ID", help="Move a step in --plan.")
    parser.add_argument(
        "--before", metavar="ID", help="Place --move-task before this step."
    )
    parser.add_argument(
        "--complete-task", metavar="ID", help="Manually complete a step in --plan."
    )
    parser.add_argument(
        "--note", default="", help="Completion note; required for a stale step."
    )
    parser.add_argument(
        "--reviews", action="store_true", help="Read stored model advice and freshness."
    )
    parser.add_argument(
        "--promote-review",
        metavar="ID",
        help="Explicitly add current stored advice to --plan; remains advice.",
    )


def validate_workspace_arguments(parser, args):
    selected = any(
        (
            args.plans,
            args.plan,
            args.create_plan,
            args.reviews,
            args.move_task,
            args.complete_task,
            args.promote_review,
        )
    )
    if (
        sum(
            bool(value)
            for value in (args.plans, args.plan, args.create_plan, args.reviews)
        )
        > 1
    ):
        parser.error("choose one of --plans, --plan, --create-plan or --reviews")
    if selected and any(
        (
            args.no_state,
            args.from_report,
            args.task,
            args.defer,
            args.restore,
            args.history,
            args.review,
        )
    ):
        parser.error(
            "plan and stored review actions require a separate live scan with local state"
        )
    if (
        sum(
            bool(value)
            for value in (args.move_task, args.complete_task, args.promote_review)
        )
        > 1
    ):
        parser.error("choose one plan mutation at a time")
    if any((args.move_task, args.complete_task, args.promote_review)) and not args.plan:
        parser.error("plan mutations require --plan NAME")
    if bool(args.move_task) != bool(args.before):
        parser.error("--move-task and --before must be supplied together")
    if args.note and not args.complete_task:
        parser.error("--note requires --complete-task")
    if (
        any((args.plan_task, args.prerequisite, args.acceptance_check))
        and not args.create_plan
    ):
        parser.error(
            "plan tasks, prerequisites and acceptance checks require --create-plan"
        )
    if args.create_plan and not args.plan_task:
        parser.error("--create-plan requires at least one --plan-task ID")


def run_workspace_actions(args, root, scope, queue):
    from skylos.cleanup_plans import (
        create_cleanup_plan,
        view_cleanup_plans,
        move_cleanup_plan_task,
        complete_cleanup_plan_task,
    )
    from skylos.cleanup_review_state import view_cleanup_reviews, promote_cleanup_review

    if args.create_plan:
        create_cleanup_plan(
            root,
            scope,
            queue,
            args.create_plan,
            args.plan_task,
            prerequisites=args.prerequisite,
            acceptance_checks=args.acceptance_check,
        )
        queue["plan"] = view_cleanup_plans(root, scope, queue, args.create_plan)
    elif args.plan:
        if args.move_task:
            move_cleanup_plan_task(
                root, scope, queue, args.plan, args.move_task, before=args.before
            )
        elif args.complete_task:
            complete_cleanup_plan_task(
                root, scope, queue, args.plan, args.complete_task, note=args.note
            )
        elif args.promote_review:
            promote_cleanup_review(root, scope, queue, args.promote_review, args.plan)
        queue["plan"] = view_cleanup_plans(root, scope, queue, args.plan)
    elif args.plans:
        queue["plans"] = view_cleanup_plans(root, scope, queue)
    elif args.reviews:
        queue["stored_reviews"] = view_cleanup_reviews(root, scope)
