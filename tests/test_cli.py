"""Tests for G-CEDD CLI."""

import pytest
from unittest.mock import patch
from g_cedd.cli import build_parser


class TestCLI:
    """Test CLI argument parsing and functionality."""

    def test_build_parser(self):
        """Test argument parser creation."""
        parser = build_parser()
        assert parser is not None

        # Test scan command
        args = parser.parse_args(["scan", "--targets", "http://example.com"])
        assert args.command == "scan"
        assert args.targets == ["http://example.com"]
        assert args.timeout == 10.0
        assert args.concurrency == 10

    def test_parser_help(self):
        """Test parser help output."""
        parser = build_parser()
        # Should not raise an exception
        try:
            parser.parse_args(["--help"])
        except SystemExit:
            pass  # Expected for --help

    @patch("g_cedd.cli.print_banner")
    def test_main_no_args(self, mock_banner):
        """Test main function with no arguments."""
        from g_cedd.cli import main

        with patch("sys.argv", ["g-cedd"]):
            with patch("g_cedd.cli.build_parser") as mock_parser:
                mock_parser.return_value.parse_args.return_value.command = None
                with patch("sys.exit") as mock_exit:
                    main()
                    mock_exit.assert_called_once_with(0)

    def test_scan_command_parsing(self):
        """Test scan command argument parsing."""
        parser = build_parser()

        args = parser.parse_args([
            "scan",
            "--targets", "http://test1.com", "http://test2.com",
            "--timeout", "5.0",
            "--concurrency", "5",
            "--rate-limit", "0.5",
            "--output", "test.json"
        ])

        assert args.command == "scan"
        assert args.targets == ["http://test1.com", "http://test2.com"]
        assert args.timeout == 5.0
        assert args.concurrency == 5
        assert args.rate_limit == 0.5
        assert args.output == "test.json"

    def test_secrets_command_parsing(self):
        """Test secrets command argument parsing."""
        parser = build_parser()

        args = parser.parse_args([
            "secrets",
            "--dir", "/tmp/test",
            "--extensions", ".env", ".yml",
            "--output", "secrets.json"
        ])

        assert args.command == "secrets"
        assert args.directory == "/tmp/test"
        assert args.extensions == [".env", ".yml"]
        assert args.output == "secrets.json"