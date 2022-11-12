#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

import dotslash

artifacts = dotslash.DotSlashMultiFileArtifact(
    executable="./traceviz",
    host=dotslash.SandcastleHost.FBCODE_LINUX,
    entries={
        "traceviz": dotslash.BuckBuild(
            cwd="fbcode",
            target="//hermetic_infra/reverie/experimental/traceviz:main",
            flags=["@//mode/opt"],
            strip=False,
            buck_cmd=dotslash.BuckCommand.BUCK2,
        ),
        "traceviz_plugin.so": dotslash.BuckBuild(
            cwd="fbcode",
            target="//hermetic_infra/reverie/experimental/traceviz:traceviz-tool[shared]",
            flags=["@//mode/opt"],
            strip=False,
            buck_cmd=dotslash.BuckCommand.BUCK2,
        ),
        "sabre": dotslash.BuckBuild(
            cwd="fbcode",
            target="fbsource//third-party/sabre:sabre",
            flags=["@//mode/opt"],
            strip=False,
            buck_cmd=dotslash.BuckCommand.BUCK2,
        ),
    },
)

spec = dotslash.Spec(
    dotslash_files=[
        dotslash.DotSlashFile(
            destination_files=[],
            oncall="hermit",
            platforms={
                dotslash.InstallPlatform.LINUX: artifacts,
            },
        )
    ],
    minify=True,
    reviewers=[],
    needs_human_approval=False,
    storage=dotslash.Storage.EVERSTORE,
)

dotslash.export_spec_object(spec)
