#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the Elastic Search output module CLI arguments helper."""

import argparse
import unittest

from plaso.cli.helpers import elastic_output
from plaso.lib import errors
from plaso.output import elastic

from tests.cli import test_lib as cli_test_lib
from tests.cli.helpers import test_lib


class ElasticSearchOutputArgumentsHelperTest(
    test_lib.OutputModuleArgumentsHelperTest):
  """Tests the Elastic Search output module CLI arguments helper."""

  # pylint: disable=no-member,protected-access

  _EXPECTED_OUTPUT = """\
usage: cli_helper.py [--index_name INDEX_NAME]
                     [--flush_interval FLUSH_INTERVAL] [--raw_fields]
                     [--elastic_user ELASTIC_USER]
                     [--elastic_password ELASTIC_PASSWORD] [--use_ssl]
                     [--ca_certificates_file_path CA_CERTIFICATES_FILE_PATH]
                     [--elastic_url_prefix ELASTIC_URL_PREFIX]
                     [--server HOSTNAME] [--port PORT]

Test argument parser.

optional arguments:
  --ca_certificates_file_path CA_CERTIFICATES_FILE_PATH
                        Path to a file containing a list of root certificates
                        to trust.
  --elastic_password ELASTIC_PASSWORD
                        Password to use for Elasticsearch authentication.
                        WARNING: use with caution since this can expose the
                        password to other users on the system. The password
                        can also be set with the environment variable
                        PLASO_ELASTIC_PASSWORD.
  --elastic_url_prefix ELASTIC_URL_PREFIX
                        URL prefix for elastic search.
  --elastic_user ELASTIC_USER
                        Username to use for Elasticsearch authentication.
  --flush_interval FLUSH_INTERVAL
                        Events to queue up before bulk insert to
                        ElasticSearch.
  --index_name INDEX_NAME
                        Name of the index in ElasticSearch.
  --port PORT           The port number of the server.
  --raw_fields          Export string fields that will not be analyzed by
                        Lucene.
  --server HOSTNAME     The hostname or server IP address of the server.
  --use_ssl             Enforces use of ssl.
"""

  def testAddArguments(self):
    """Tests the AddArguments function."""
    argument_parser = argparse.ArgumentParser(
        prog='cli_helper.py',
        description='Test argument parser.', add_help=False,
        formatter_class=cli_test_lib.SortedArgumentsHelpFormatter)

    elastic_output.ElasticSearchOutputArgumentsHelper.AddArguments(
        argument_parser)

    output = self._RunArgparseFormatHelp(argument_parser)
    self.assertEqual(output, self._EXPECTED_OUTPUT)

  def testParseOptions(self):
    """Tests the ParseOptions function."""
    options = cli_test_lib.TestOptions()

    output_mediator = self._CreateOutputMediator()
    output_module = elastic.ElasticsearchOutputModule(output_mediator)
    elastic_output.ElasticSearchOutputArgumentsHelper.ParseOptions(
        options, output_module)

    with self.assertRaises(errors.BadConfigObject):
      elastic_output.ElasticSearchOutputArgumentsHelper.ParseOptions(
          options, None)


if __name__ == '__main__':
  unittest.main()
