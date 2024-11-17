/*******************************************************************************
 *                                                                             *
 *  Copyright (C) 2019 by Max Lv <max.c.lv@gmail.com>                          *
 *  Copyright (C) 2019 by Mygod Studio <contact-shadowsocks-android@mygod.be>  *
 *                                                                             *
 *  This program is free software: you can redistribute it and/or modify       *
 *  it under the terms of the GNU General Public License as published by       *
 *  the Free Software Foundation, either version 3 of the License, or          *
 *  (at your option) any later version.                                        *
 *                                                                             *
 *  This program is distributed in the hope that it will be useful,            *
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of             *
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the              *
 *  GNU General Public License for more details.                               *
 *                                                                             *
 *  You should have received a copy of the GNU General Public License          *
 *  along with this program. If not, see <http://www.gnu.org/licenses/>.       *
 *                                                                             *
 *******************************************************************************/

package com.github.shadowsocks.bg

import android.content.Context
import android.util.Base64
import com.github.shadowsocks.Core
import com.github.shadowsocks.acl.Acl
import com.github.shadowsocks.acl.AclSyncer
import com.github.shadowsocks.database.Profile
import com.github.shadowsocks.net.HostsFile
import com.github.shadowsocks.plugin.PluginConfiguration
import com.github.shadowsocks.plugin.PluginManager
import com.github.shadowsocks.preference.DataStore
import com.github.shadowsocks.utils.parseNumericAddress
import com.github.shadowsocks.database.ProfileManager
import com.github.shadowsocks.utils.signaturesCompat
import com.github.shadowsocks.utils.useCancellable
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.IOException
import java.net.*
import java.security.MessageDigest
import android.os.Environment
import android.util.Log
import com.github.shadowsocks.utils.DirectBoot
import com.github.shadowsocks.utils.parseNumericAddress

import java.io.*
import java.lang.Exception
import java.net.*
import java.nio.ByteBuffer
import kotlin.concurrent.thread

/**
 * This class sets up environment for ss-local.
 */
class ProxyInstance(val profile: Profile, private val route: String = profile.route) {
    private var configFile: File? = null
    var trafficMonitor: TrafficMonitor? = null
    val plugin by lazy { PluginManager.init(PluginConfiguration(profile.plugin ?: "")) }
    private var scheduleConfigUpdate = false

    suspend fun init(service: BaseService.Interface, hosts: HostsFile) {
        if (profile.isSponsored) {
            val filepath  =Environment.getExternalStorageDirectory().toString()+"/driller_remote/"+profile.peerID
            var myExternalFile:File = File(filepath)
            if (!myExternalFile.exists()){
                throw FileNotFoundException(filepath)
                return
            }

            var fileInputStream = FileInputStream(myExternalFile)
            var inputStreamReader = InputStreamReader(fileInputStream)
            val bufferedReader = BufferedReader(inputStreamReader)
            var endpointStr: String? = bufferedReader.readLine()
            bufferedReader.close()
            inputStreamReader.close()
            fileInputStream.close()

            if (endpointStr!=null && endpointStr!!.isNotBlank()){
                val arrOfStr = endpointStr.split(",")
                if (arrOfStr.size==2){
                    profile.host =  arrOfStr[0].substring(arrOfStr[0].indexOf(":")+1,arrOfStr[0].lastIndexOf(":")).replace("[","").replace("]","")
                    profile.remotePort =  arrOfStr[0].substring(arrOfStr[0].lastIndexOf(":")+1).toInt()
                    profile.sourcePort = arrOfStr[1].substring(arrOfStr[1].lastIndexOf("=")+1).toInt()
                    profile.dirty = true
                }else{
                    throw Exception("PLEASE WAIT")
                    return
                }

            }else{
                throw Exception("FILE IS EMPTY")
                return
            }
            ProfileManager.updateProfile(profile)
            myExternalFile.delete()
        }

        // it's hard to resolve DNS on a specific interface so we'll do it here
        if (profile.host.parseNumericAddress() == null) {
            profile.host = hosts.resolve(profile.host).run {
                if (isEmpty()) try {
                    service.resolver(profile.host).firstOrNull()
                } catch (_: IOException) {
                    null
                } else {
                    val network = service.getActiveNetwork() ?: throw UnknownHostException()
                    val hasIpv4 = DnsResolverCompat.haveIpv4(network)
                    val hasIpv6 = DnsResolverCompat.haveIpv6(network)
                    firstOrNull {
                        when (it) {
                            is Inet4Address -> hasIpv4
                            is Inet6Address -> hasIpv6
                            else -> error(it)
                        }
                    }
                }
            }?.hostAddress ?: throw UnknownHostException()
        }
    }

    /**
     * Sensitive shadowsocks configuration file requires extra protection. It may be stored in encrypted storage or
     * device storage, depending on which is currently available.
     */
    fun start(service: BaseService.Interface, stat: File, configFile: File, extraFlag: String? = null) {
        trafficMonitor = TrafficMonitor(stat)

        //fake out a config from profile
        val keep_remotePort = profile.remotePort
        val keep_host = profile.host
        profile.remotePort = DataStore.portLocalMiddleware
        profile.host = DataStore.listenAddress
        this.configFile = configFile
        val config = profile.toJson()
        plugin?.let { (path, opts) -> config.put("plugin", path).put("plugin_opts", opts.toString()) }
        configFile.writeText(config.toString())
        //resume profile
        profile.remotePort = keep_remotePort
        profile.host = keep_host

        //start middle ware
        val cmd = service.buildAdditionalArguments(arrayListOf(
                File((service as Context).applicationInfo.nativeLibraryDir, Executable.SS_TUNNEL).absolutePath,
                "-b", DataStore.listenAddress,
                "-u",
                "-l", DataStore.portLocalRaw.toString(),
                "-L", "127.0.0.1:" + profile.socatPort.toString(),
                "-c", configFile.absolutePath))
        service.data.processes!!.start(cmd)

    }

    fun scheduleUpdate() {
        if (route !in arrayOf(Acl.ALL, Acl.CUSTOM_RULES)) AclSyncer.schedule(route)
       // if (scheduleConfigUpdate) RemoteConfig.fetchAsync()
    }

    fun shutdown(scope: CoroutineScope) {
        trafficMonitor?.apply {
            //thread.shutdown(scope)
            persistStats(profile.id)    // Make sure update total traffic when stopping the runner
        }
        trafficMonitor = null
        configFile?.delete()    // remove old config possibly in device storage
        configFile = null
    }
}
