import os
import re

test_dir = 'test'
larpc_test_libs = ['boost_system-mt', 'boost_thread-mt', 'gflags', 'glog', 'gmock', 'gtest', 'protobuf']

def TestTool(target, source, env, **kwargs):
    global lib_larpc, test_dir, test_util, test_protobuf_cc
    test_name = os.path.splitext(source[0].name)[0]
    test_binary = test_dir + os.path.sep + test_name + '_runner'
    prog = env.Program(test_binary, [source[0], 'proto/test_config.pb.o'] + [test_dir + os.path.sep + x for x in ['framework_main.cc', 'network_pipe.cc']], LIBS=larpc_test_libs + lib_larpc)

    test_config_filename = test_binary + ".cfg"
    test_gen_commands = re.search(r'^/\*\* TestConfig: ([^*]*)\*/$', source[0].get_contents(), flags=re.MULTILINE)
    tg_target = env.Command(test_config_filename, source[0], '$TESTUTIL --test_config=$TARGET -gen_test_config ' + (test_gen_commands and test_gen_commands.group(1) or ''))
    run_target = env.Command('run_test_' + test_name, test_binary, test_binary + ' --test_config=' + test_dir + os.path.sep + test_name + '.cfg')

    env.Depends(tg_target, test_util)
    env.Depends(run_target, tg_target)
    env.Depends(run_target, prog)
    env.Depends('ut_' + test_name, run_target)
    env.AlwaysBuild('ut_' + test_name)

def TestToolEmitter(target, source, env):
    del target[:]
    for s in source:
        test_name = os.path.splitext(s.name)[0]
        target.append('ut_' + test_name)
    return (target, source)

env = Environment(BUILDERS = {'test': Builder(action=TestTool, emitter=TestToolEmitter)},
                  tools = ['default', 'protoc'],
                  ENV = os.environ)

env.Append(CPPPATH = ["/usr/local/include"])
env.Append(CPPPATH = ["/usr/local/ssl/include"])
env.Append(CPPPATH = [".", "src"])
env.Append(LIBPATH = "/usr/local/lib")
env.Append(CPPFLAGS = ['-g'])

## liblarpc construction parameters

protobuf_cc = filter(lambda x: str(x).find(".cc") > -1, env.Protoc(None, ["proto/larpc.proto"], PROTOCPYTHONOUTDIR=None))

obj_sources = Glob("src/*.cc") + protobuf_cc

larpc_libs = ['crypto', 'glog', 'protobuf', 'ssl']

lib_larpc = env.SharedLibrary("larpc", obj_sources, LIBS=['boost_' + x + '-mt' for x in ['filesystem', 'system', 'thread']] + larpc_libs)

test_protobuf_cc = filter(lambda x: str(x).find(".cc") > -1, env.Protoc(None, ["proto/test_config.proto"], PROTOCPYTHONOUTDIR=None))

test_util = env.Program('test/framework_utils', ['test/framework_utils.cc'] + test_protobuf_cc, LIBS=lib_larpc + larpc_test_libs)

env.test(None, Glob("test/*_test.cc"), TESTUTIL=test_util[0].get_abspath())

