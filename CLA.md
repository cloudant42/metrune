# Metrune Individual Contributor License Agreement

Thank you for contributing to Metrune. This agreement clarifies the terms under
which your contributions are provided, and protects both you and the project.

You keep the copyright in everything you contribute. This agreement grants a
licence; it does not transfer ownership, and it does not stop you using your own
work anywhere else.

By signing, you accept the terms below for your present and future
contributions to this project.

## 1. Definitions

**"Project Maintainer"** means Florian Allgöwer, the current maintainer of
Metrune, together with any successor entity to which the Project Maintainer
assigns these rights under section 8.

**"You"** means the individual who signs this agreement.

**"Contribution"** means any work of authorship, including any modification of
or addition to an existing work, that You intentionally submit to the Project
Maintainer for inclusion in Metrune. "Submit" means any form of electronic,
verbal, or written communication sent to the Project Maintainer or its
representatives, including but not limited to pull requests, issues, and
electronic mailing lists, excluding communication conspicuously marked or
otherwise designated in writing by You as "Not a Contribution".

## 2. Copyright licence

You grant to the Project Maintainer, and to recipients of software distributed
by the Project Maintainer, a perpetual, worldwide, non-exclusive, no-charge,
royalty-free, irrevocable copyright licence to reproduce, prepare derivative
works of, publicly display, publicly perform, sublicense, and distribute Your
Contributions and such derivative works.

The right to sublicense means the Project Maintainer may distribute Your
Contribution under licence terms other than the project's own, including
commercial terms. Section 7 limits how that right may be exercised.

## 3. Patent licence

You grant to the Project Maintainer, and to recipients of software distributed
by the Project Maintainer, a perpetual, worldwide, non-exclusive, no-charge,
royalty-free, irrevocable (except as stated in this section) patent licence to
make, have made, use, offer to sell, sell, import, and otherwise transfer
Metrune. This licence applies only to those patent claims licensable by You that
are necessarily infringed by Your Contribution alone or by combination of Your
Contribution with Metrune.

If any entity institutes patent litigation against You or any other entity
alleging that Your Contribution, or Metrune to which You have contributed,
constitutes direct or contributory patent infringement, then any patent licences
granted to that entity under this agreement for that Contribution or that work
terminate as of the date such litigation is filed.

## 4. Your representations

You represent that:

1. You are legally entitled to grant the above licences.
2. Each of Your Contributions is Your original creation, or You have identified
   its source and any licence or other restriction under section 5.
3. If Your employer has rights to intellectual property that You create, You
   have received permission to make Your Contributions on behalf of that
   employer, that Your employer has waived such rights, or that Your employer
   has executed a separate corporate agreement with the Project Maintainer.

## 5. Third-party work

Should You wish to submit work that is not Your original creation, You may
submit it separately from any Contribution, identifying the complete details of
its source and of any licence or other restriction of which You are personally
aware, and conspicuously marking the work as "Submitted on behalf of a
third-party: [named here]".

## 6. No obligations

You are not expected to provide support for Your Contributions, except to the
extent You wish to do so. Unless required by applicable law or agreed in
writing, You provide Your Contributions on an "AS IS" BASIS, WITHOUT WARRANTIES
OR CONDITIONS OF ANY KIND, either express or implied, including, without
limitation, any warranties or conditions of TITLE, NON-INFRINGEMENT,
MERCHANTABILITY, or FITNESS FOR A PARTICULAR PURPOSE.

The Project Maintainer is under no obligation to accept or include any
Contribution.

## 7. Commitment to keep contributions open

This section limits the sublicensing right granted in section 2, and is a
binding commitment by the Project Maintainer to You.

The Project Maintainer will continue to make Your Contribution available under
the Apache License 2.0, or under another licence approved by the Open Source
Initiative, for as long as the Project Maintainer distributes it.

The Project Maintainer may additionally distribute Your Contribution under
other terms, including as part of a commercial or hosted offering. That
additional licensing never withdraws the open source availability required by
the paragraph above.

In plain terms: your contribution can be included in a paid edition, but it
cannot be taken out of the open source project.

## 8. Assignment

The Project Maintainer may assign this agreement and the rights granted under it
to a successor entity, including a company later formed by the Project
Maintainer to develop Metrune, or an acquirer of the Metrune project. The
commitment in section 7 binds any such successor.

## 9. Notification

You agree to notify the Project Maintainer of any facts or circumstances of
which You become aware that would make these representations inaccurate in any
respect.

---

## How to sign

Add yourself to `signatures/cla.json` in your first pull request:

```json
{
  "githubUsername": "your-github-username",
  "name": "Your Full Name",
  "signedAt": "2026-07-29",
  "claVersion": "1.0"
}
```

That entry, in a commit authored by you, is your signature. It is recorded in
this repository's history rather than with a third-party service, and it covers
all of your future contributions — you will not be asked again.

You can check before opening the pull request:

```bash
scripts/check-cla.py your-github-username
```
