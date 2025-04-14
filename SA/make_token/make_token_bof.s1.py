from typing import List, Tuple

from outflank_stage1.task.base_bof_task import BaseBOFTask
from outflank_stage1.task.enums import BOFArgumentEncoding


class MakeTokenBOF(BaseBOFTask):
    def __init__(self):
        super().__init__("make_token_bof", base_binary_name="make_token")

        self.parser.add_argument("username", help="The username to impersonate in DOMAIN\username format.")
        self.parser.add_argument("password", help="The password for the corresponding user.")

        self.parser.description = "Create a network only token for the corresponding user."

    def _encode_arguments_bof(self, arguments: List[str]) -> List[Tuple[BOFArgumentEncoding, str]]:
        parser_arguments = self.parser.parse_args(arguments)

        domain, username = parser_arguments.username.split('\\', 1)

        encoded_arguments = [
            (BOFArgumentEncoding.STR, domain),
            (BOFArgumentEncoding.STR, username),
            (BOFArgumentEncoding.STR, parser_arguments.password),
        ]

        return encoded_arguments
