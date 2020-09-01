Contributing to PyPSSST
=======================

Your bug reports, comments, suggestions, enhancements or new code are welcomed.

Bug reports, feature requests and suggestions
---------------------------------------------

If you need to report report a bug then you can submit an issue to the
`issue tracker`_ on GitHub. Please search through the existing issues
before submitting a new one to see if the problem you have is a known
issues; if it is then it is helpful for everyone if you simply add
extra information to the existing issue. If you do find a new problem
it is very helpful if you include code to reproduce the issue in the
report.


Reporting security vulnerabilities
----------------------------------

In the (hopefully unlikely) event that you find a critical security
issue you can post sensitive parts of your report to the issue tracker
by encrypting them with PSSST! The public key for reporting security
issues is
``a5de76b8b629c84d9b7e03fb86a5b3fac4a38c25885738fe4953fd7674ee7659``,
and you can encrypt your message using the the following code
fragment:

.. code-block:: python
                
   import pssst
   client = pssst.PSSSTClient('a5de76b8b629c84d9b7e03fb86a5b3fac4a38c25885738fe4953fd7674ee7659')
   secret_message = "The Magic Words are Squeamish Ossifrage"
   packet, _ = client.pack_request(secret_message.encode("UTF8"))
   print(packet.hex())

You can then include the resulting hex-encoded block into your report.


Contributing code
-----------------

If you have additions, enhancements or improvements to the code (or
documentation) that you'd like to submit for inclusion then please
submit a `pull request`_ to the GitHub project. All input it welcomed
but please take a moment to read the following guidelines before
sumitting your PR.

Testing
~~~~~~~

A configuration file for tox_ is provided. If you want to contribute
code then please install ``tox`` *and run it* before submitting you
code.

If you add new functionality them please also **write tests** for the
new code. The existing ``tox`` configuration uses the ``pytest``
framework. Please add tests for your new code either by adding new
test cases to the existing ``test_*.py`` files in the ``tests/``
directory or by adding a new file there. We aim for (and check for)
complete code coverage in testing and as well as seeking complete
testing of all functional paths through the code.


Code style
~~~~~~~~~~

This project seeks to follow the standard Python `PEP 8`_ style
guildlines, with the slight modification that we allow line lengths up
to 100 characters (since these days most people have monitors that are
wider then 80 columns). While insisting on code style may seem picky,
it does help both with readability and with making merging of
differences much easier. The ``tox`` configuration will run both
``pylint`` and ``flake8`` on your code and will whine in an
irritating way if your code does not comply.


Copyright and license
~~~~~~~~~~~~~~~~~~~~~

This project is released under the MIT_ license. See :any:`license`
for the details. If you with to have your code included in the project
then you will need to consent to your code being released under the
same license. Please also include a copytight header in any new files,
based on the headers in the existing files.

.. _issue tracker: https://github.com/nickovs/pypssst/issues
.. _pull request: https://github.com/nickovs/pypssst/pulls
.. _PEP 8: https://www.python.org/dev/peps/pep-0008
.. _tox: https://pypi.org/project/tox/
.. _pytest: https://pypi.org/project/pytest/
.. _MIT: https://opensource.org/licenses/MIT
