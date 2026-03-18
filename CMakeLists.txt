# CMakeLists.txt — UBX over UDP Wireshark plugin (in-tree build)
#
# Copy this folder to wireshark/plugins/epan/ubx-udp/ and add
# plugins/epan/ubx-udp to CUSTOM_PLUGIN_SRC_DIR in CMakeListsCustom.txt.
#
# SPDX-License-Identifier: GPL-2.0-or-later

include(WiresharkPlugin)

# Plugin name and version info (major minor micro extra)
set_module_info(ubx-udp 1 0 0 0)

set(DISSECTOR_SRC
  packet-ubx-udp.c
)

set(PLUGIN_FILES
  plugin.c
  ${DISSECTOR_SRC}
)

set(CLEAN_FILES
  ${PLUGIN_FILES}
)

set_source_files_properties(
  ${CLEAN_FILES}
  PROPERTIES
  COMPILE_FLAGS "${WERROR_COMMON_FLAGS}"
)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

register_plugin_files(
  plugin.c
  plugin
  ${DISSECTOR_SRC}
)

add_wireshark_plugin_library(ubx-udp epan)

target_link_libraries(ubx-udp epan)

install(TARGETS ubx-udp
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/${CPACK_PACKAGE_NAME}/plugins/${CPACK_PACKAGE_VERSION} NAMELINK_SKIP
  RUNTIME DESTINATION ${CMAKE_INSTALL_LIBDIR}/${CPACK_PACKAGE_NAME}/plugins/${CPACK_PACKAGE_VERSION}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/${CPACK_PACKAGE_NAME}/plugins/${CPACK_PACKAGE_VERSION}
)

file(GLOB_RECURSE DISSECTOR_HEADERS ${CMAKE_CURRENT_SOURCE_DIR}/*.h)
CHECKAPI(
  NAME
    ubx-udp
  SWITCHES
    -g abort -g termoutput -build
  SOURCES
    ${DISSECTOR_SRC}
    ${DISSECTOR_HEADERS}
)

#
# Editor modelines  -  http://www.wireshark.org/tools/modelines.html
#
# Local variables:
# c-basic-offset: 8
# tab-width: 8
# indent-tabs-mode: t
# End:
#
# vi: set shiftwidth=8 tabstop=8 noexpandtab:
# :indentSize=8:tabSize=8:noTabs=false:
