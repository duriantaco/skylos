## Changelog

## [4.13.1](https://github.com/duriantaco/skylos/compare/v4.13.0...v4.13.1) (2026-05-10)


### Bug Fixes

* **python:** detect no-effect statements ([#332](https://github.com/duriantaco/skylos/issues/332)) ([7ffa1c9](https://github.com/duriantaco/skylos/commit/7ffa1c9fa52ea80c52a22580d22d23901d1b5405))
* **python:** detect unreachable loop code ([#334](https://github.com/duriantaco/skylos/issues/334)) ([676a414](https://github.com/duriantaco/skylos/commit/676a414b495a8997495f61402c896cfeeb7ee5b1))
* **python:** keep same-name wrappers dead ([#330](https://github.com/duriantaco/skylos/issues/330)) ([7d4d32c](https://github.com/duriantaco/skylos/commit/7d4d32c3ece94ed4fcbe72cdf43fe5d6c7f43c1c))
* **security:** harden agent service and API surfaces ([#335](https://github.com/duriantaco/skylos/issues/335)) ([05393ea](https://github.com/duriantaco/skylos/commit/05393ea444903ea0ba94bde039a0824b0fef4b87))

## [4.13.0](https://github.com/duriantaco/skylos/compare/v4.12.1...v4.13.0) (2026-05-09)


### Features

* **languages:** add Dart support and harden PHP scanning ([#327](https://github.com/duriantaco/skylos/issues/327)) ([681e754](https://github.com/duriantaco/skylos/commit/681e75409bef06976afbeb5f78206dca28cbf782))
* **languages:** harden Java and Go security flows ([#323](https://github.com/duriantaco/skylos/issues/323)) ([4f02b69](https://github.com/duriantaco/skylos/commit/4f02b69d6673e030491046b42819fadb0f95264b))
* **quality:** add architecture policy and placeholder checks ([#318](https://github.com/duriantaco/skylos/issues/318)) ([15e6be4](https://github.com/duriantaco/skylos/commit/15e6be4c55e233e077b18f9496332878f51925cc))


### Bug Fixes

* **analyzer:** keep scanner caches at project root ([#324](https://github.com/duriantaco/skylos/issues/324)) ([294a03c](https://github.com/duriantaco/skylos/commit/294a03c8c1f852c68f701a8b1999b9ab44a47ff7))
* **architecture:** add Q802 Q803 remediation hints ([#326](https://github.com/duriantaco/skylos/issues/326)) ([2f0f3f0](https://github.com/duriantaco/skylos/commit/2f0f3f0b8eaf5d76f3908b8702a8ca9d3ba9449d))
* **gate:** make file-level IAD architecture findings advisory ([#325](https://github.com/duriantaco/skylos/issues/325)) ([1df7ee1](https://github.com/duriantaco/skylos/commit/1df7ee166e0655445625fdfad4c321a1fd658267))
* **python:** keep pyproject GUI scripts live ([#328](https://github.com/duriantaco/skylos/issues/328)) ([151b7e2](https://github.com/duriantaco/skylos/commit/151b7e2ffea42cc792adbb1e149075bd3e9383a5))
* **python:** suppress override method parameters ([#329](https://github.com/duriantaco/skylos/issues/329)) ([2a5cba3](https://github.com/duriantaco/skylos/commit/2a5cba37a77fa21df3a82bc7efdf6004e534f61b))


### Documentation

* **readme:** simplify hero section ([#319](https://github.com/duriantaco/skylos/issues/319)) ([8aa979e](https://github.com/duriantaco/skylos/commit/8aa979e143e6d0b209f13fce800d69fcb09ad85a))

## [4.12.1](https://github.com/duriantaco/skylos/compare/v4.12.0...v4.12.1) (2026-05-08)


### Bug Fixes

* **architecture:** repair Q802/Q803 audit defects ([#316](https://github.com/duriantaco/skylos/issues/316)) ([633e911](https://github.com/duriantaco/skylos/commit/633e911e17bfb4e2f62ac42175ebe528ddd29359))
* **architecture:** suppress private helper Q803 false positives ([#315](https://github.com/duriantaco/skylos/issues/315)) ([8ec8799](https://github.com/duriantaco/skylos/commit/8ec8799264fef70c60bb40ae33e9575af60fac6a))
* **cli:** quiet LLM scan output ([#313](https://github.com/duriantaco/skylos/issues/313)) ([f13fff2](https://github.com/duriantaco/skylos/commit/f13fff2c3798005221243b8294ce22711161958f))

## [4.12.0](https://github.com/duriantaco/skylos/compare/v4.11.1...v4.12.0) (2026-05-07)


### Features

* **vscode:** add review queue provenance ([#303](https://github.com/duriantaco/skylos/issues/303)) ([280239a](https://github.com/duriantaco/skylos/commit/280239ab39593326956a792e73ea5766633ff720))


### Bug Fixes

* **architecture:** rename misleading healthy zone fallback ([#308](https://github.com/duriantaco/skylos/issues/308)) ([3eba72c](https://github.com/duriantaco/skylos/commit/3eba72c7ba641a9ce350a16d030df40ce2397012))
* **architecture:** suppress library re-export false positives ([#307](https://github.com/duriantaco/skylos/issues/307)) ([117142d](https://github.com/duriantaco/skylos/commit/117142d24aa0ed3a1ed822fa471efd58d09a9d1d))

## [4.11.1](https://github.com/duriantaco/skylos/compare/v4.11.0...v4.11.1) (2026-05-06)


### Bug Fixes

* **architecture:** suppress cli entrypoint false positives ([#301](https://github.com/duriantaco/skylos/issues/301)) ([73886c9](https://github.com/duriantaco/skylos/commit/73886c9ec74722b3278331677c050d44c98240a6))

## [4.11.0](https://github.com/duriantaco/skylos/compare/v4.10.0...v4.11.0) (2026-05-05)


### Features

* **cicd:** add AI PR risk passport ([#294](https://github.com/duriantaco/skylos/issues/294)) ([750faa4](https://github.com/duriantaco/skylos/commit/750faa4ed69e0a22bfdcbf1b2b34f94f7625255f))
* **cicd:** add PR evidence cards ([#291](https://github.com/duriantaco/skylos/issues/291)) ([10b21fd](https://github.com/duriantaco/skylos/commit/10b21fd02a2705e59e4a9dc0065a6675b782ab42))
* **debt:** show saved history ([#287](https://github.com/duriantaco/skylos/issues/287)) ([8b4a4c1](https://github.com/duriantaco/skylos/commit/8b4a4c113d024a5271d0e2a1340d5ee11a33ac24))
* **defend:** add versioned OWASP coverage ([#295](https://github.com/duriantaco/skylos/issues/295)) ([355b4f2](https://github.com/duriantaco/skylos/commit/355b4f20b51f67f7dba4a48e130e56ae638bcb63))
* **quality:** add standards-backed practice enforcement ([#283](https://github.com/duriantaco/skylos/issues/283)) ([c432260](https://github.com/duriantaco/skylos/commit/c4322607a2869b89272cb1f62787e91c294ce28c))
* **security:** flag mixed-script paths ([#288](https://github.com/duriantaco/skylos/issues/288)) ([8689902](https://github.com/duriantaco/skylos/commit/8689902eeb81cd2c02623748a70aada93b5810ff))
* **security:** flag unverified webhook handlers ([#289](https://github.com/duriantaco/skylos/issues/289)) ([4127578](https://github.com/duriantaco/skylos/commit/4127578429209c1a12066928bc1075484985e16d))


### Bug Fixes

* **architecture:** preserve submodule coupling targets ([#296](https://github.com/duriantaco/skylos/issues/296)) ([90a1e1d](https://github.com/duriantaco/skylos/commit/90a1e1df882606c83d113c3fcc9a6c6ee5da2cd8))
* **cli:** repair display severity filtering ([#280](https://github.com/duriantaco/skylos/issues/280)) ([0c3b929](https://github.com/duriantaco/skylos/commit/0c3b929eaa5ea8791e904ced79b0cba784d8406c))


### Documentation

* **contributing:** add contributor roadmap ([#292](https://github.com/duriantaco/skylos/issues/292)) ([d398b8a](https://github.com/duriantaco/skylos/commit/d398b8a56b425f017f34a879412da39d8ae387ea))
* **security:** document webhook signature rule ([#290](https://github.com/duriantaco/skylos/issues/290)) ([3024850](https://github.com/duriantaco/skylos/commit/3024850207ee929c15bba459a04bd5a4aa0aa50d))

## [Unreleased]

### Documentation
- Document SKY-D282 webhook signature verification coverage.

## [4.10.0](https://github.com/duriantaco/skylos/compare/v4.9.0...v4.10.0) (2026-05-02)


### Features

* **analyzer:** add configurable vibe guardrails ([b789334](https://github.com/duriantaco/skylos/commit/b78933488deee7b3a40e6bb7c2fae44f93d76587))
* **analyzer:** add Python liveness evidence for dead-code detection ([#272](https://github.com/duriantaco/skylos/issues/272)) ([f5c53b3](https://github.com/duriantaco/skylos/commit/f5c53b372ef7aa848cd900a3410f9e15d5d92950))
* **cli:** add concise IDE-friendly output ([#279](https://github.com/duriantaco/skylos/issues/279)) ([07d22cc](https://github.com/duriantaco/skylos/commit/07d22cccc21eb57c6e8a655940934dda6a99e16d))


### Bug Fixes

* **analyzer:** cover rust and workspace edge cases ([721235b](https://github.com/duriantaco/skylos/commit/721235be475aae526a95ce35a2a82ebfe69ec083))
* **analyzer:** harden rust and monorepo resolution ([565fc8f](https://github.com/duriantaco/skylos/commit/565fc8f52626260680c02b7d751a485ba06ee23f))
* **analyzer:** restore configurable vibe guardrails ([#271](https://github.com/duriantaco/skylos/issues/271)) ([61aa187](https://github.com/duriantaco/skylos/commit/61aa187e6d3d2337e000f81e7e343ef9e0f99420))
* **ci:** harden enterprise workflow generation ([#268](https://github.com/duriantaco/skylos/issues/268)) ([8568bc0](https://github.com/duriantaco/skylos/commit/8568bc0a2d899656e86ebbd966040686aa404643))
* **cli, quality:** honor gate exits and ignore annotation strings ([#275](https://github.com/duriantaco/skylos/issues/275)) ([5a8d3f6](https://github.com/duriantaco/skylos/commit/5a8d3f6430b9bb93d419c8465b189071d12cff32))
* **cli:** honor strict scan exit codes ([#278](https://github.com/duriantaco/skylos/issues/278)) ([b98db50](https://github.com/duriantaco/skylos/commit/b98db508eafab2e9b4ce1549d21851f0476a5760))
* **sync:** block direct main pushes ([#269](https://github.com/duriantaco/skylos/issues/269)) ([9ed6fe6](https://github.com/duriantaco/skylos/commit/9ed6fe62ab74ce92cb16500085acc676d0363156))

## [4.9.0](https://github.com/duriantaco/skylos/compare/v4.8.0...v4.9.0) (2026-04-30)


### Features

* **analyzer:** add rust scanner and monorepo support ([d2cb1b7](https://github.com/duriantaco/skylos/commit/d2cb1b753e712b988abdb9902d1ce40e39c8f2e0))

## [4.8.0](https://github.com/duriantaco/skylos/compare/v4.7.0...v4.8.0) (2026-04-28)


### Features

* **cli:** add upload session metadata ([0758f77](https://github.com/duriantaco/skylos/commit/0758f77bca606f5f4e046ccc481e638779738d19))


### Performance Improvements

* **analyzer:** reduce scan runtime without changing findings ([#264](https://github.com/duriantaco/skylos/issues/264)) ([9cff0c4](https://github.com/duriantaco/skylos/commit/9cff0c4b38870bb99c093a95f9fb0b710ddfd6be))


### Documentation

* **ci:** add tokenless CI workflow example ([723ec78](https://github.com/duriantaco/skylos/commit/723ec78274b92bf6c996c3863375ecc00174ecf9))
* **readme:** add validation results and trust badge ([f359184](https://github.com/duriantaco/skylos/commit/f35918427a5a2e2cde1e5e4edccc4f1fb1b11cd2))

## [4.7.0](https://github.com/duriantaco/skylos/compare/v4.6.0...v4.7.0) (2026-04-26)


### Features

* **cloud:** support tokenless CI auth ([60b3273](https://github.com/duriantaco/skylos/commit/60b3273c0f671242cdd7a1ab9256686845ba35cb))


### Bug Fixes

* **release:** restore release-please metadata flow ([f4e233c](https://github.com/duriantaco/skylos/commit/f4e233c5139685f60c468401fcbb2f099521bd4e))

## [4.6.0](https://github.com/duriantaco/skylos/compare/v4.5.0...v4.6.0) (2026-04-26)


### Features

* **languages:** add js-jsx support and strengthen java-go security c… ([#237](https://github.com/duriantaco/skylos/issues/237)) ([c082fcf](https://github.com/duriantaco/skylos/commit/c082fcfe0ea3d72529fdc42e45dfed1436de3aa7))
* **languages:** add php foundation support ([#243](https://github.com/duriantaco/skylos/issues/243)) ([4a137cc](https://github.com/duriantaco/skylos/commit/4a137cc6838fb946f93ad50ba3e4d208d2995fa2))
* **languages:** deepen go java and js-ts security checks ([#238](https://github.com/duriantaco/skylos/issues/238)) ([fde84e3](https://github.com/duriantaco/skylos/commit/fde84e3941dd3f6f80fdba283086dff932fffa0e))
* **languages:** deepen js-ts reachability and entry discovery ([#240](https://github.com/duriantaco/skylos/issues/240)) ([6ea96a2](https://github.com/duriantaco/skylos/commit/6ea96a25a1ac39a429ef5a63108c8dd939db048a))
* **languages:** harden go archive symlink checks ([#241](https://github.com/duriantaco/skylos/issues/241)) ([4d37f14](https://github.com/duriantaco/skylos/commit/4d37f14b0b966310cc73ea97191be1a2c70a83e2))
* **languages:** harden java canonical path guard checks ([#242](https://github.com/duriantaco/skylos/issues/242)) ([d3958bf](https://github.com/duriantaco/skylos/commit/d3958bf3686220d9486718b61493ae0290556d63))
* **security:** add security contract regression detection ([#236](https://github.com/duriantaco/skylos/issues/236)) ([1b48e52](https://github.com/duriantaco/skylos/commit/1b48e525d75ae1c4a57f856e47b53ddc5fd73088))
* **upload:** add family-aware cloud uploads and debt reporting ([#239](https://github.com/duriantaco/skylos/issues/239)) ([55b75ea](https://github.com/duriantaco/skylos/commit/55b75eabc1a9207a5e465d11ce5057dc01df6887))
* **upload:** add monorepo routing and sonar import ([#244](https://github.com/duriantaco/skylos/issues/244)) ([dc473d7](https://github.com/duriantaco/skylos/commit/dc473d77858cc6535ef7639fc1dfe4b3dd5dcf72))


### Bug Fixes

* **dead-code:** improve frozen benchmark precision and recall ([#254](https://github.com/duriantaco/skylos/issues/254)) ([4fd170c](https://github.com/duriantaco/skylos/commit/4fd170cf629a2d4d3a2345202ea935e44d9486fd))
* **java:** make security flow analysis structured ([#253](https://github.com/duriantaco/skylos/issues/253)) ([5d3a946](https://github.com/duriantaco/skylos/commit/5d3a946808210972af55afb237599626ee098d52))
* **python:** fix critical logic gaps ([#245](https://github.com/duriantaco/skylos/issues/245)) ([96712b9](https://github.com/duriantaco/skylos/commit/96712b94f061b8edeb7f0abfa11bf4a1d58b3b76))
* **python:** improve security flow precision and recall ([#250](https://github.com/duriantaco/skylos/issues/250)) ([8af25d2](https://github.com/duriantaco/skylos/commit/8af25d216a30ab93c46e92e0dfe0bc073949e176))
* **quality:** detect duplicate branch logic ([#255](https://github.com/duriantaco/skylos/issues/255)) ([8e76e9d](https://github.com/duriantaco/skylos/commit/8e76e9dde0b791d4758d210ba7eaefa821402776))
* **security:** improve typescript ssrf and go command precision ([#251](https://github.com/duriantaco/skylos/issues/251)) ([1218c9d](https://github.com/duriantaco/skylos/commit/1218c9dad2186c72a73545ce7cac335f4f742b13))


### Documentation

* **readme:** refresh GHCR image release notes ([#232](https://github.com/duriantaco/skylos/issues/232)) ([bea165c](https://github.com/duriantaco/skylos/commit/bea165c5c661c0efbe3db5ab7e39203a9c909a4d))
* **readme:** streamline landing pages and benchmark scorecard ([#256](https://github.com/duriantaco/skylos/issues/256)) ([f2af8c2](https://github.com/duriantaco/skylos/commit/f2af8c20565bb542be8aa1845f59351dd72b36af))

## [4.5.0](https://github.com/duriantaco/skylos/compare/v4.4.0...v4.5.0) (2026-04-22)


### Features

* **docker:** publish official GHCR image for Skylos CLI ([#230](https://github.com/duriantaco/skylos/issues/230)) ([0300f87](https://github.com/duriantaco/skylos/commit/0300f87997c0497f23b368a2f2ccbc609dab199e))
* **docker:** publish official GHCR image for Skylos CLI ([#231](https://github.com/duriantaco/skylos/issues/231)) ([96cc2b7](https://github.com/duriantaco/skylos/commit/96cc2b795c102fb29de55072b8097c8966d22f46))
* **security:** add challenge pass for uncertain findings ([#226](https://github.com/duriantaco/skylos/issues/226)) ([a2b2927](https://github.com/duriantaco/skylos/commit/a2b2927e6a7c019fcadc0bf41e41cb4027a69153))
* **security:** add review evidence for llm security findings ([#218](https://github.com/duriantaco/skylos/issues/218)) ([1670cde](https://github.com/duriantaco/skylos/commit/1670cde0cec58f8e8cc3a4645ec993f1fb877718))
* **security:** add security taskflow foundation and relax local pre-commit gate ([#221](https://github.com/duriantaco/skylos/issues/221)) ([1fa404b](https://github.com/duriantaco/skylos/commit/1fa404bc3f82d218f62b12336481be0b586844b5))
* **security:** add taskflow candidate ledger ([#222](https://github.com/duriantaco/skylos/issues/222)) ([2459fb6](https://github.com/duriantaco/skylos/commit/2459fb6e214c8482d5af89967ff87706cbc986a1))
* **security:** add taskflow file facts ([#223](https://github.com/duriantaco/skylos/issues/223)) ([78cc52c](https://github.com/duriantaco/skylos/commit/78cc52c6f7ff5de971359bd44f0c7db463573c35))
* **security:** persist taskflow run artifacts ([#225](https://github.com/duriantaco/skylos/issues/225)) ([3338eef](https://github.com/duriantaco/skylos/commit/3338eef2564d7dddece9761344381d797d23cb06))


### Bug Fixes

* **cli:** improve pre-commit UX and harden large upload flow ([#210](https://github.com/duriantaco/skylos/issues/210)) ([30fa686](https://github.com/duriantaco/skylos/commit/30fa686fd051ee39ca3049386d36ad75c23a290a))
* **cli:** reduce false positives in local pre-commit gating ([#213](https://github.com/duriantaco/skylos/issues/213)) ([e0b3a3e](https://github.com/duriantaco/skylos/commit/e0b3a3e4d562a655e2333e67bd4d31d9ad5b760c))
* **cli:** reduce false positives in local pre-commit gating ([#214](https://github.com/duriantaco/skylos/issues/214)) ([5959fa8](https://github.com/duriantaco/skylos/commit/5959fa8ce3ad4d5e1937aebada649886e51abb59))
* **cli:** scan staged test files for secrets only ([#215](https://github.com/duriantaco/skylos/issues/215)) ([9b1f199](https://github.com/duriantaco/skylos/commit/9b1f199f800144f60a2c976c442dcb1887a6763a))


### Documentation

* **readme:** add security taskflow example ([#227](https://github.com/duriantaco/skylos/issues/227)) ([6434f2a](https://github.com/duriantaco/skylos/commit/6434f2aa5b38537e5e11174e326f59a9fc4ec02e))
* **readme:** update security taskflow docs ([#224](https://github.com/duriantaco/skylos/issues/224)) ([251fe4d](https://github.com/duriantaco/skylos/commit/251fe4d52aec576e87f96189ce4d938e6fe766bd))

## [4.4.0](https://github.com/duriantaco/skylos/compare/v4.3.2...v4.4.0) (2026-04-16)


### Features

* **cli:** add suite command for the full local bundle ([#209](https://github.com/duriantaco/skylos/issues/209)) ([1989905](https://github.com/duriantaco/skylos/commit/198990555adbebc1bda52fecf306a639a31616cf))
* **py:** add repo-aware vibe reference detection ([#208](https://github.com/duriantaco/skylos/issues/208)) ([797b1ab](https://github.com/duriantaco/skylos/commit/797b1ab83f25cfe0f2a282eb2140b41c8e65d41f))
* **ts:** add AI defense beta for direct LLM integrations ([#207](https://github.com/duriantaco/skylos/issues/207)) ([dfb4fda](https://github.com/duriantaco/skylos/commit/dfb4fdab761a7fed233c92d96f29cae8fcb25aac))
* **ts:** report monorepo workspace inventory ([#202](https://github.com/duriantaco/skylos/issues/202)) ([610c53b](https://github.com/duriantaco/skylos/commit/610c53b427ad73a7d8e002393dc868cdb78bcd8a))


### Bug Fixes

* **ci:** publish releases from tags ([#196](https://github.com/duriantaco/skylos/issues/196)) ([be5e6ee](https://github.com/duriantaco/skylos/commit/be5e6eee92fe48b1b48410946fa3ddba6c9cf709))
* **ts:** keep monorepo package entrypoints reachable ([#205](https://github.com/duriantaco/skylos/issues/205)) ([f0cb594](https://github.com/duriantaco/skylos/commit/f0cb5944d9dee5a7334406f0789ce5b1ffe48dea))
* **ts:** resolve direct project references in monorepos ([#204](https://github.com/duriantaco/skylos/issues/204)) ([c2b4c69](https://github.com/duriantaco/skylos/commit/c2b4c6928c970ceb5de48c0352dc27f17e36c1e8))
* **ts:** use declared workspaces for monorepo resolution ([#203](https://github.com/duriantaco/skylos/issues/203)) ([5a28512](https://github.com/duriantaco/skylos/commit/5a2851288dd61f27fcf6181e3c8a6eeb55bdd2fb))

## [4.3.2](https://github.com/duriantaco/skylos/compare/v4.3.1...v4.3.2) (2026-04-10)


### Bug Fixes

* **sync:** support top-level cloud pull config ([#194](https://github.com/duriantaco/skylos/issues/194)) ([8abe838](https://github.com/duriantaco/skylos/commit/8abe838e61689ca1bcf23920a289d830f172e58e))
* **ts:** resolve workspace exports and local imports maps ([#181](https://github.com/duriantaco/skylos/issues/181)) ([322466c](https://github.com/duriantaco/skylos/commit/322466c617c4af95af854ff9a11973158688b0d3))

## [4.3.1](https://github.com/duriantaco/skylos/compare/v4.3.0...v4.3.1) (2026-04-08)


### Bug Fixes

* **upload:** support large scan uploads via artifact transport ([#179](https://github.com/duriantaco/skylos/issues/179)) ([7f1641f](https://github.com/duriantaco/skylos/commit/7f1641f5fdda4970e310ad96836618b6dba96124))

## [4.3.0](https://github.com/duriantaco/skylos/compare/v4.2.1...v4.3.0) (2026-04-08)


### Features

* **cli:** add explicit project selection flow ([#171](https://github.com/duriantaco/skylos/issues/171)) ([3eb3001](https://github.com/duriantaco/skylos/commit/3eb30014c06cc5b4e96ed599298cc551010a7d3a))


### Bug Fixes

* **core:** honor root ignores and actionable clean edits ([#165](https://github.com/duriantaco/skylos/issues/165)) ([358dd1f](https://github.com/duriantaco/skylos/commit/358dd1f4a18f523fb0a4301ab7f15c43d8febfb0))
* **release:** align release-please bootstrap with 4.2.1 ([8fb330f](https://github.com/duriantaco/skylos/commit/8fb330fb0f8905defa7574b919be04db3188b3fe))
* **summary:** include Java in language analysis summary ([#175](https://github.com/duriantaco/skylos/issues/175)) ([433c0e8](https://github.com/duriantaco/skylos/commit/433c0e886fed3e1fab19bce3b9238141aa870b96))
* **ts:** align Next.js convention coverage ([#164](https://github.com/duriantaco/skylos/issues/164)) ([05264b2](https://github.com/duriantaco/skylos/commit/05264b2e32a440aad2549dd74ce66c7b7cc54176))

## [Unreleased]

### Added
- Added a Simplified Chinese README (`README_CN.md`)
- Added configurable web UI port support for `skylos run` via `--port` or `SKYLOS_PORT`
- Added monorepo workspace inventory reporting for TypeScript projects. Skylos now reports root packages, child workspaces from `package.json` / `pnpm-workspace.yaml`, `tsconfig.json` references, and undeclared workspace package diagnostics in analysis and MCP output
- Added TypeScript AI defense beta support to `skylos discover` / `skylos defend` for direct Node / Next-style LLM integrations, reusing the existing guardrail engine and report format
- Added `skylos suite <path>` as a single local command for static analysis, technical debt, AI defense, and provenance summary

### Changed
- SKY-L030: Lint rule for `except Exception`/`except BaseException` with trivial handler (CWE-396)
- Continue CLI cleanup by extracting command boundaries, lazy-loading heavy analysis paths.Expanded regression guardrails around dispatch, output, and exit-code behavior
- TypeScript monorepo resolution now uses declared workspaces as the package boundary, resolves root package self-imports, and honors JSONC-style `tsconfig` path inheritance
- TypeScript resolution now supports importer-local direct `tsconfig.json` project references for composite monorepos without leaking those references into global package resolution
- TypeScript dead-file and unnecessary-export analysis now treats workspace package entrypoints as reachability roots, including packages kept alive through direct local `tsconfig.json` project references
- AI defense file discovery for `discover` / `defend` now scans direct TypeScript and JavaScript source files in addition to Python
- Docs, help, and tour now steer new users toward a smaller command set centered on `skylos suite .`, `skylos .`, `skylos cicd init`, and the agent commands

### Fixed
- Browser login callback now validates `state` and verifies the returned token metadata via `whoami`
- Fixed local web UI rendering to avoid unsafe HTML insertion patterns
- Sync credentials are written with stricter file and dir permissions

## [4.2.1] - 2026-04-03

### Changed
- `skylos agent scan` now defaults to the fast review path. Slow dead-code verification is opt-in via `--verify-dead-code`
- Agent review is more repo-aware, with better file selection and context for quality, security, and debt-style issues
- Added agent benchmarks and Codex comparison runs with token reporting

### Fixed
- Agent scans now fail cleanly on missing API keys instead of crashing
- Review output is clearer when dead-code verification is still running
- LLM provider and runtime settings now propagate correctly through the agent path

## [4.2.0] - 2026-03-30

### Added
- Added `skylos debt <path>` for technical debt hotspot analysis
- Added separate structural debt scoring and hotspot `priority_score`

### Changed
- Refactored the CLI entrypoint by extracting `baseline`, `badge`, `doctor`, `credits`, `init`, `whitelist`, `clean`, `whoami`, `login`, `sync`, `city`, `discover`, `defend`, `debt`, `ingest`, `provenance`, and `cicd` into dedicated command modules. 
- CLI refactor guardrails to catch dispatch, output, and exit-code regressions during future `cli.py` cleanup
- `skylos debt --top` now will override `report.top`
- Changed-file debt scans now resolve git diffs from the repository root and include `.js` / `.jsx`
- Debt baseline and history writes require project-root scans
- Debt baseline comparisons no longer count unseen hotspots as resolved
- Sync-installed pre-push hooks now run only the fast Rust/Python parity guard instead of a full `skylos .` scan, and checked-in Skylos hooks are limited to the `pre-commit` stage

### Fixed
- `skylos agent watch --learn` now forwards the learning flag into the watch loop

## [4.1.4] - 2026-03-25

### Fixed
- `skylos --llm` now shows populated `Problem:` descriptions for dead code findings instead of blank lines (fixes [#118](https://github.com/duriantaco/skylos/issues/118))
- Dead code findings in `--llm` output now include rule IDs (SKY-DC001–SKY-DC006) and proper severity levels
- `uvx skylos` crash on Windows due to litellm's `.pth` file exceeding MAX_PATH (260 chars) in uvx cache paths (fixes [#120](https://github.com/duriantaco/skylos/issues/120))
- Skylos now honors project `.gitignore` entries during file discovery, so ignored worktrees, custom virtualenvs, and other excluded paths are no longer scanned
- Flask, FastAPI, Starlette, and Sanic imperative route or lifecycle registration (`add_url_rule`, `add_api_route`, `add_route`, `register_listener`, `register_middleware`) is now treated as a live framework entrypoint instead of dead code
- Pytest and Pluggy hook implementations (`@pytest.hookimpl`, `@hookimpl`) are now treated as live plugin entrypoints instead of dead code
- Grep cache saves now fail open on non-writable roots instead of aborting analysis

### Changed
- `litellm` moved from required to optional dependency — install with `pip install skylos[llm]` for LLM features. Core static analysis no longer pulls in litellm.
- `litellm` version capped at `<1.82.8` to avoid known supply chain compromise
- Agent scans are faster on changed-file workflows, and fix generation is now opt-in
- Phase 2b LLM audits now focus on high-signal files instead of scanning the full Python set
- Static `grep_verify` now reuses `.skylos/cache/grep_results.json` across repeated local scans

## [4.1.3] - 2026-03-22

### Added
- Configurable duplicate string threshold — `duplicate_strings` in `[tool.skylos]` (default: 3)
- CLI table now prints a brief explanation of what each column means
- CLI discoverability overhaul — `skylos` with no args shows grouped command overview of all 30+ commands
- `skylos commands` — flat alphabetical listing of every command
- `skylos tour` — guided 6-step walkthrough for new users
- README Command Reference section with grouped tables
- `nudges` config key in `[tool.skylos]` to suppress post-scan suggestions
- Java language support. Dead code, security and quality
- Spring/JUnit framework awareness — `@Override`, `@Bean`, `@Test`, `@GetMapping`, `@Scheduled`, lifecycle methods are suppressed

### Fixed
- Django/DRF false positives: `Meta` inner classes, `urlpatterns`, `serializer_class`, `permission_classes`, `filterset_class`, migration attrs, and `AppConfig` subclasses are fixed (fixes [#115](https://github.com/duriantaco/skylos/issues/115))
- Added `django_filters` to framework detection

### Changed
- Quality table column renamed from "Function" to "Name"
- Duplicate string findings now show `repeated 5× (max 3)` instead of cryptic `5 (target ≤ 3)`
- Complexity findings now show `Complexity: 14 (max 10)` instead of bare `14 (target ≤ 10)`
- `skylos init` template now includes `duplicate_strings` option
- Post-scan hints replaced with context-aware nudges (1 per scan, based on results)
- Argparse epilog simplified — points to `skylos commands` and `skylos tour`

## [4.1.2] - 2026-03-20

### Added
- MCP `validate_code_change` — diff-level validation with security regression detection, dangerous pattern scanning, secret leak detection, and SQL injection checks
- CI/CD review integration with security regression detection from diffs
- Upload payload now includes `definitions` for Code City dashboard
- Auto-detect changed files from git for quality checks when no explicit diff base is provided

### Fixed
- Crash on systems without clipboard mechanism (Docker, headless Linux) — `pyperclip.PyperclipException` is now caught
- False positive on framework methods in nested classes
- Removed unused `DJANGO_SIGNAL_METHODS` import in penalties module

## [4.1.0] - 2026-03-20

### Added
- Security regression detection — SKY-L021 expanded to 13 categories: input validation, security headers, encryption, logging/audit, sanitization, permission checks. Findings include `control_type` field
- Web scanner — public scan page at `skylos.dev/scan`, paste a GitHub URL, get a vibe code risk score. No signup, rate-limited (10/IP/hr)
- MCP guardrails — `validate_code_change` (diff validation for regressions, dangerous patterns, secrets) and `get_security_context` (project security posture for agents)
- Community rules — `skylos rules install|list|remove|validate` for YAML rule packs from `duriantaco/skylos-rules` or any URL. Taint-flow pattern support in YAML rules
- AI provenance — `--provenance` flag annotates findings with AI authorship (cursor, copilot, claude, etc.). Per-agent and per-severity breakdowns
- TypeScript dead code detection — cross-file analysis with SKY-E003 (unused files with transitive propagation), SKY-E004 (unnecessary exports), wildcard re-export chain resolution, `.js`→`.ts` path resolution
- TypeScript export graph — aliased imports, default re-exports, namespace re-exports all tracked correctly
- Python vibe detection — phantom security calls/decorators now resolve imported local modules and package re-exports like `security.require_auth()` and `@guards.require_auth`
- Next.js security — SKY-D280 (missing auth in API routes), SKY-S102 (server secrets in `"use client"` files), SKY-D281 (SQL injection in `"use server"` actions)
- SKY-S102: Client-side secret exposure in `static/`, `public/`, `.next/`, `dist/`, `build/` paths
- D230 enhanced: catches `redirect(request.args.get("next", "/"))` with `urlparse`/`startswith` guard suppression
- SKY-Q306: Cognitive complexity (SonarQube S3776)
- SKY-L027 (duplicate strings), SKY-L028 (too many returns), SKY-L029 (boolean trap)
- Go quality rules (Q301, Q302, C303, C304) via tree-sitter-go
- `skylos[fast]` — optional Rust accelerator
- `skylos provenance` — detect AI-authored code in PRs
- Agent-aware quality gate (`[tool.skylos.gate.agent]`)
- `skylos agent watch`, `agent pre-commit`, `agent verify --fix --pr`
- Grep-based verification pass with parallel workers, GrepCache, CWE tagging + SARIF taxonomy

### Changed
- Agent CLI consolidated from 16 to 8 commands
- TS definitions use `filename:name` as dict key (prevents collisions)

### Fixed
- `Definition.to_dict()` now includes `is_exported` flag
- TS def key collisions and cross-file import resolution

## [4.0.0] - 2026-03-15

### Added
- `-a` / `--all` flag — enables `--danger`, `--secrets`, `--quality`, and `--sca` in one shot
- `addopts` config — set default CLI flags in `pyproject.toml` under `[tool.skylos]`
- LLM verification agent — `skylos agent verify <path>` with 3-pass dead code verification
- Batch LLM calls — up to 8 findings per call
- Confidence feedback loop — auto-tunes heuristic weights across runs (`~/.skylos/feedback.json`)
- MCP `verify_dead_code` tool
- `--verification-mode` flag — `judge_all` and `production` modes
- AI defense cloud dashboard — `skylos defend . --upload` sends results to Skylos Cloud
- `skylos cicd init --defend` and `skylos-defend` pre-commit hook
- Public API detection — documented API symbols suppressed without LLM calls

### Changed
- Dead-code verifier defaults to `judge_all` mode
- Deterministic suppressors attached as verifier evidence

### Fixed
- Quality Gate step runs with `if: always()`
- `--upload` on empty project prints "skipping upload"

## [3.5.10] - 2026-03-10

### Changed
- Breaking: Removed `skylos . --fix`, `skylos agent fix`, `skylos agent analyze --fix` — use `skylos agent remediate`

### Fixed
- `LiteLLMAdapter.complete()` forwards `response_format` to litellm
- `create_llm_adapter()` passes `base_url` from `AgentConfig`
- Attribute context matching bug, `_mark_refs()` O(n) fallback replaced with lookup
- Narrowed broad `except Exception` blocks to specific types
- Git subprocess calls now have timeouts

## [3.5.9] - 2026-03-10

### Fixed
- `skylos cicd init` no longer crashes with `TypeError` on `generate_workflow()`

## [3.5.8] - 2026-03-10

### Fixed
- SKY-D260: multiline HTML comment duplicates, overly broad patterns, fenced code block exclusion, homoglyph false positives, single-line string regex
- SKY-Q301: counts comprehension `for`/`if` and match case guards; threshold `>=10` → `>10`

## [3.5.7] - 2026-03-09

### Added
- `skylos cicd init --upload` for cloud dashboard workflows
- SKY-L016 (undefined config), SKY-L023 (phantom decorator), SKY-L024 (stale mock), SKY-L026 (unfinished generation)
- SKY-D260: AI supply chain security — multi-file prompt injection scanner
- Vibe confidence metadata (`vibe_category`, `ai_likelihood`)
- `--llm` flag for LLM-optimized reports

### Fixed
- SKY-C401 clone detection false positives reduced

## [3.5.6] - 2026-03-07

### Added
- `--diff [BASE_REF]` — line-level precision filtering using unified diff hunk headers
- Git blame attribution on findings
- Auto-upload for linked projects (`--no-upload` to skip)
- SKY-L010 (security TODOs), SKY-L011 (disabled security controls), SKY-L012 (phantom calls), SKY-L013 (insecure randomness), SKY-L014 (hardcoded credentials), SKY-L017 (error info disclosure), SKY-L020 (overly broad permissions)
- Dynamic signal tracking (`inspect.getmembers`, `dir()`)
- Expanded default exclude folders for Go, TypeScript, VCS, IDE

### Fixed
- `--exclude-folder` with trailing slashes and CWD-relative paths

### Changed
- Table output is now the default (TUI opt-in via `--tui`)
- MCP credit checks fail-open on network errors

## [3.5.5] - 2026-03-04

### Added
- Claude Code Security integration — `skylos ingest claude-security` CLI subcommand
- `skylos cicd init --claude-security` generates 3-job GitHub Actions workflow
- Blue "Claude Security" badges on dashboard

### Changed
- Credit deduction is format-aware (2 credits for Claude Security, 1 for native)

## [3.5.4] - 2026-03-03

### Added
- LLM-generated code-level fix suggestions with before/after snippets
- PR inline comments with fenced code blocks, collapsible `<details>` in summary
- Rule-based text suggestion fallback when LLM not used

### Fixed
- Phase 3 matching for findings without `rule_id`
- `_merge_llm_findings` passes through `vulnerable_code` and `fixed_code`

## [3.5.3] - 2026-03-03

### Added
- CVE reachability analysis via ca9 engine — proves whether vulnerable deps are actually reachable
- `skylos whoami` command

### Fixed
- `--json -o <file>` writes to file instead of only stdout
- CI/CD workflow: `agent review` uses `--format json`, auto-adds `ANTHROPIC_API_KEY`
- PR review inline comments: absolute vs relative path mismatch fixed

## [3.5.2] - 2026-03-01

### Added
- Go dead code detection

### Fixed
- `engines/__init__.py` missing

## [3.5.1] - 2026-02-28

### Added
- TypeScript analysis 6.7x faster via batched tree-sitter queries
- 11 new TypeScript security rules: SKY-D245 through SKY-D253, SKY-D270, SKY-D271, SKY-D510
- SKY-Q305 (duplicate condition), SKY-Q402 (await in loop), SKY-UC002 (unreachable code)
- Shannon entropy-based secret detection
- Smarter attribute resolution, `__init__.py` re-export tracking
- Expanded Django/DRF framework dictionaries
- Go language support

### Fixed
- TUI category list focusable again

## [3.4.3] - 2026-02-25

### Added
- Multi-path CLI support (`skylos app/ tests/`)
- `@abstractmethod` suppression, framework dictionaries for Starlette, Flask-RESTful, Tornado, Marshmallow, SQLAlchemy, Celery, Click

### Fixed
- Pattern tracker double-counting, `private_name` penalty 80→60

## [3.4.2] - 2026-02-22

### Added
- Next.js/React TypeScript dead code detection (convention exports, route handlers, hooks)
- Dynamic dispatch: `getattr(module, f"prefix_{var}")` and `globals()` f-string detection
- `__init_subclass__` registry pattern detection, indirect enum inheritance

### Fixed
- Pattern tracker regex compilation, inline f-string handling, enum method/class variable detection

## [3.4.1] - 2026-02-21

### Added
- BFS from entry points through import graph for false positive elimination
- `__getattr__` package handling, relative import resolution
- `skylos credits` command, MCP server auth + rate limiting + credit deduction

### Fixed
- `--trace --json` and `--pytest-fixtures --json` producing invalid JSON

## [3.4.0] - 2026-02-18

### Added
- TypeScript: interface, enum, and type alias dead code detection
- TUI language display and severity bar chart
- CI/CD visibility: `skylos badge` command, "30-second setup" in README
- CBO coupling (SKY-Q701) and LCOM cohesion (SKY-Q702)
- Architecture metrics: SKY-Q802 (distance from Main Sequence), SKY-Q803 (Zone of Pain/Uselessness), SKY-Q804 (Dependency Inversion violations)

### Fixed
- TypeScript class name capture, `regex.exec()` false positives, lifecycle method exclusion
- `export default function`, `export { name }`, `extends Base` tracking
- Callbacks, array storage, object shorthand, return values, spread, type annotations as references

### Changed
- TypeScript scanner uses `Query()` constructor instead of deprecated `TS_LANG.query()`

## [3.3.0] - 2026-02-13

### Added
- Remediation agent — `skylos agent remediate` with `--dry-run`, `--max-fixes`, `--auto-pr`, `--test-cmd`, `--severity`
- CI/CD integration — `skylos cicd init|gate|annotate|review`
- MCP server — `analyze`, `security_scan`, `quality_check`, `secrets_scan`, `remediate` tools
- SKY-D230 (open redirect), SKY-D231 (CORS), SKY-D232 (JWT), SKY-D233 (deserialization), SKY-D234 (mass assignment)
- Sanitizer framework for taint analysis (XSS, CMD, URL, PATH)
- TypeScript security: SKY-D503 through SKY-D507, SKY-D240 through SKY-D244
- SKY-L005 (unused exception var), SKY-L006 (inconsistent return), SKY-Q501 (god class)
- TypeScript quality: SKY-Q601 through SKY-Q604
- Go language support via pluggable engine architecture
- Secrets scanning expanded to `.env`, `.yaml`, `.json`, `.toml`, `.ini`, `.cfg`, `.ts`, `.tsx`, `.js`, `.go`

### Fixed
- `import json` inside `main()` shadowing module-level import
- LLM false-aliving all `_`-prefixed dead code

### Changed
- Taint-flow scanners accept context-specific sanitizer sets
- `danger.py` shares parsed AST tree across scanners

## [3.2.5] - 2026-02-09

### Fixed
- `exclude_folders` wired through `run_pipeline` and `run_static_on_files`

## [3.2.4] - 2026-02-08

### Changed
- Agent analyze/review refactored from parallel execution to pipeline architecture (static analysis as source of truth, LLM verifies)
- LLM no longer independently discovers dead code

### Added
- `DeadCodeVerifierAgent` with call graph evidence and defs_map context
- `pipeline.py` with `run_pipeline` and `run_static_on_files`

### Fixed
- Circular dependency checker feeding `.ts`/`.go` files to `ast.parse()`

## [3.2.3] - 2026-02-07

### Fixed
- Hallucination detection PyPI "missing" status
- Dependency parsing for pyproject.toml and setup.py (extras, project name inclusion)

## [3.2.1] - 2026-02-05

### Fixed
- Import usage counting: aliases no longer mark the wrong module as used

## [3.2.0] - 2026-02-05

### Added
- `graph.py` for taint analysis, data flow, and context slicing
- `FalsePositiveFilterAgent` for LLM-based static finding verification
- CI auto-detection (GitHub Actions, Jenkins, CircleCI, GitLab CI) with PR number extraction
- Type2 clone detection, circular dependency display
- CLI entrypoint decorator patterns, post-scan upload CTA, upload prompt with "don't remind me" preference
- SKY-Q401 (async blocking)

### Changed
- `visitor.py` with call graph construction and dynamic string reference detection
- `analyzer.py` uses `CodeGraph` for deep security audits
- Hardened SKY-L001 (catches `list()`, `dict()`, `set()` constructors, comprehensions)

### Fixed
- Parent dir search for pyproject.toml/requirements.txt, dist-info name parsing, Python 3.13 AST compat

## [3.1.3] - 2026-01-27

### Added
- Centralized LLM runtime resolver with auto-detection from `--model`
- Symbol context tracking in taint visitors
- `skylos key` command

### Changed
- Two-level dependency hallucination: SKY-D222 (CRITICAL, confirmed hallucinated) and SKY-D223 (MEDIUM, exists but undeclared)

## [3.1.2] - 2026-01-25

### Added
- Console entrypoint parsing from `pyproject.toml` `[project.scripts]`
- `--pytest-fixtures` flag for unused fixture detection
- Dependency hallucination detection
- Custom rules and compliance from web app (beta)

### Changed
- CLI displays paths relative to CWD
- Switched to `uv` in CI workflows, `litellm` adapter, upload made optional

### Removed
- `cache.py` (unstable outputs), anthropic/openai adapters (replaced by litellm)

## [3.1.1] - 2026-01-20

### Added
- `--provider`, `--base-url` flags and env variable support for LLM providers
- Auto API key bypass for local endpoints
- LLM-assisted detection agent

### Fixed
- `--gate` uploads before exiting, pre-commit hook exit codes, Protocol interface false positives

### Changed
- `OpenAIAdapter` uses Chat Completions API, provider resolution priority chain

## [3.0.3] - 2026-01-10

### Added
- Protocol and ABC detection with duck typing (≥70% method overlap)
- Mixin, base class, and framework lifecycle method confidence penalties
- Data class field detection (dataclass, NamedTuple, Enum, attrs, Pydantic)
- Optional dependency import handling (`try`/`except ImportError`)

### Changed
- `# noqa` comment support for line-level suppression

## [3.0.1] - 2026-01-08

### Added
- `--trace` flag for runtime call tracing via `sys.settrace()`
- Progress indicator during analysis
- SKY-U002: dead file detection for empty Python files
- AST body masking, framework-aware entrypoint detection
- Config-based dead code suppression (`pyproject.toml` whitelists with patterns, reasons, expiration dates)
- `skylos whitelist` command
- Confidence column in output
- Expanded soft patterns (visitor, pytest hooks, plugins)

### Changed
- Replaced `--coverage` with `--trace`
- Penalty system: hard entrypoints (confidence=0), framework entrypoints (with context), soft patterns (proportional)

### Fixed
- Flask route detection, `@login_required` handling, Pydantic route type hints
- `ComplexityRule` visitor, Python 3.13 compat, `skylos init` duplicate config sections

## [2.7.1] - 2025-12-23

### Fixed
- Missing `skylos.visitors.languages` in package, `--version` crash, pre-commit gate script

## [2.7.0] - 2025-12-19

### Added
- Instance attribute type tracking, expanded dunder methods
- SKY-L004 (nested try blocks), SKY-U001 (unreachable code)
- `--coverage` flag, `ImplicitRefTracker` for dynamic patterns

### Fixed
- `Class(1).method()`, `self.attr.method()`, `super().method()` patterns
- Flask/FastAPI route false positives

## [2.6.0] - 2025-12-05

### Added
- TypeScript support (dead code, security, quality) via tree-sitter
- Language-specific config overrides in `pyproject.toml`
- Multi-provider AI adapters (OpenAI, Anthropic) with keyring credential storage
- AI-powered code repair (`--fix`)

## [2.5.3] - 2025-11-28

### Fixed
- Exclusion patterns ignored in analyzer, nested directory exclusion support

## [2.5.2] - 2025-11-24

### Added
- Quality gate (`--gate`) for CI/CD pipeline blocking
- Config support via `pyproject.toml` `[tool.skylos]`
- SKY-C303 (too many args), SKY-C304 (function too long), SKY-L001 (mutable default), SKY-L002 (bare except), SKY-L003 (dangerous comparison)

### Fixed
- Python 3.13 AST crash, JSON serialization of `pathlib.Path`, `DangerousComparisonRule` false positives

## [2.5.1] - 2025-11-19

### Added
- `--tree` flag for ASCII tree output
- Relative file paths in CLI

## [2.5.0] - 2025-11-12

### Added
- Code quality scanner: cyclomatic complexity and nesting depth rules

### Fixed
- Dataclass schema class false positives, multi-part module import detection

## [2.4.0] - 2025-10-14

### Added
- SKY-D211 (SQL injection), SKY-D217 (SQL raw API), SKY-D216 (SSRF), SKY-D215 (path traversal), SKY-D212 (command injection)

## [2.3.0] - 2025-09-22

### Added
- VSCode extension on marketplace
- Dangerous patterns scanner (SKY-D201 through D210), `--danger` flag, `--table` output

### Fixed
- Non-JSON prints breaking CI/CD, secrets regex false positives

## [2.2.3] - 2025-09-18

### Fixed
- Interactive remove/comment for dotted imports and class/async methods

## [2.2.2] - 2025-09-17

### Added
- Secrets scanning (SKY-S101): provider patterns + high entropy detection, `--secrets` flag
- GitHub Actions CI workflow

## [2.1.2] - 2025-08-27

### Added
- Dataclass field detection, `first_read_lineno` tracking, `visit_Global` binding

### Fixed
- Missing `_dataclass_stack` init, dataclass/global singleton false positives

## [2.1.1] - 2025-08-23

### Added
- Pre-commit hooks

## [2.1.0] - 2025-08-21

### Added
- CST-based safe edits for import/function removal via `libcst`

### Changed
- Visitor improvements: locals and types per function scope, constants handling

### Fixed
- `self.attr`/`cls.attr` false positives

## [2.0.1] - 2025-08-11

### Fixed
- Framework-aware pass: route endpoints no longer clamped to low confidence
- `_mark_refs()` rewritten for clarity

## [2.0.0] - 2025-07-14

### Added
- Front end integration (Skylos Cloud dashboard)

## [1.2.2] - 2025-07-03

### Fixed
- `self.ignored_lines` overwrite in loop

## [1.2.1] - 2025-07-03

### Added
- Comment directives: `# pragma: no skylos`, `# pragma: no cover`, `# noqa`
- `proc_file()` returns 7-tuple with ignored lines set

## [1.2.0] - 2025-06-12

### Added
- Framework detection (Flask, Django, FastAPI) with confidence scoring
- `--confidence` flag

### Fixed
- Flask/Django routes incorrectly flagged, test file exclusion improvements

## [1.1.12] - 2025-06-10

### Added
- Test file auto-detection (patterns, imports, decorators)

### Fixed
- Private item (`_`-prefix) and `__future__` import false positives

## [1.1.11] - 2025-06-08

### Added
- `--exclude-folder`, `--include-folder`, `--no-default-excludes`, `--list-default-excludes`

### Fixed
- Test class identification false positives

## [1.0.11] - 2025-05-27

### Added
- Unused parameter and variable detection

## [1.0.10] - 2025-05-24

### Changed
- Rewritten from Rust to Python (faster), benchmark infrastructure, confidence system
