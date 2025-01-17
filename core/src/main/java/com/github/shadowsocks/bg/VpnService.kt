/*******************************************************************************
 *                                                                             *
 *  Copyright (C) 2017 by Max Lv <max.c.lv@gmail.com>                          *
 *  Copyright (C) 2017 by Mygod Studio <contact-shadowsocks-android@mygod.be>  *
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

import android.app.Service
import android.content.Intent
import android.content.pm.PackageManager
import android.net.LocalSocket
import android.net.LocalSocketAddress
import android.net.Network
import android.os.Build
import android.os.ParcelFileDescriptor
import android.system.ErrnoException
import android.system.OsConstants
import android.util.Log
import com.github.shadowsocks.Core
import com.github.shadowsocks.Core.TAG
import com.github.shadowsocks.Core.currentProfile
import com.github.shadowsocks.VpnRequestActivity
import com.github.shadowsocks.acl.Acl
import com.github.shadowsocks.core.R
import com.github.shadowsocks.net.ConcurrentLocalSocketListener
import com.github.shadowsocks.net.DefaultNetworkListener
import com.github.shadowsocks.net.HostsFile
import com.github.shadowsocks.net.Subnet
import com.github.shadowsocks.preference.DataStore
import com.github.shadowsocks.utils.Key
import com.github.shadowsocks.utils.closeQuietly
import com.github.shadowsocks.utils.int
import com.github.shadowsocks.utils.printLog
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.io.*
import java.net.*
import java.nio.ByteBuffer
import java.util.*
import android.net.VpnService as BaseVpnService

class VpnService : BaseVpnService(), LocalDnsService.Interface {
    companion object {
        private var middlewareSendThread: Thread? = null
        private var middlewareRecvThread: Thread? = null

        private const val VPN_MTU = 1500
        private const val PRIVATE_VLAN6_CLIENT = "fdfe:dcba:9876::1"
        private const val PRIVATE_VLAN6_ROUTER = "fdfe:dcba:9876::2"
    }

    private inner class ProtectWorker : ConcurrentLocalSocketListener("ShadowsocksVpnThread",
            File(Core.deviceStorage.noBackupFilesDir, "protect_path")) {
        override fun acceptInternal(socket: LocalSocket) {
            socket.inputStream.read()
            val fd = socket.ancillaryFileDescriptors!!.single()!!
            try {
                socket.outputStream.write(if (underlyingNetwork.let { network ->
                            if (network != null) try {
                                DnsResolverCompat.bindSocket(network, fd)
                                return@let true
                            } catch (e: IOException) {
                                when ((e.cause as? ErrnoException)?.errno) {
                                    // also suppress ENONET (Machine is not on the network)
                                    OsConstants.EPERM, 64 -> e.printStackTrace()
                                    else -> printLog(e)
                                }
                                return@let false
                            } catch (e: ReflectiveOperationException) {
                                check(Build.VERSION.SDK_INT < 23)
                                printLog(e)
                            }
                            protect(fd.int)
                        }) 0 else 1)
            } finally {
                fd.closeQuietly()
            }
        }
    }

    inner class NullConnectionException : NullPointerException(), BaseService.ExpectedException {
        override fun getLocalizedMessage() = getString(R.string.reboot_required)
    }

    override val data = BaseService.Data(this)
    override val tag: String get() = "ShadowsocksVpnService"
    override fun createNotification(profileName: String): ServiceNotification =
            ServiceNotification(this, profileName, "service-vpn")

    private var conn: ParcelFileDescriptor? = null
    private var worker: ProtectWorker? = null
    private var active = false
    private var metered = false
    private var underlyingNetwork: Network? = null
        set(value) {
            field = value
            if (active && Build.VERSION.SDK_INT >= 22) setUnderlyingNetworks(underlyingNetworks)
        }
    private val underlyingNetworks get() =
        // clearing underlyingNetworks makes Android 9 consider the network to be metered
        if (Build.VERSION.SDK_INT == 28 && metered) null else underlyingNetwork?.let { arrayOf(it) }

    override fun onBind(intent: Intent) = when (intent.action) {
        SERVICE_INTERFACE -> super<BaseVpnService>.onBind(intent)
        else -> super<LocalDnsService.Interface>.onBind(intent)
    }

    override fun onRevoke() = stopRunner()

    override fun killProcesses(scope: CoroutineScope) {
        Log.i(TAG, "interrupt thread")
        if (middlewareSendThread != null) {
            middlewareSendThread?.interrupt()
            middlewareSendThread=null
        }

        if (middlewareRecvThread != null){
            middlewareRecvThread?.interrupt()
            middlewareSendThread=null
        }
        Log.i(TAG, "interrupted thread")


        super.killProcesses(scope)
        active = false
        scope.launch { DefaultNetworkListener.stop(this) }
        worker?.shutdown(scope)
        worker = null
        conn?.close()
        conn = null
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (DataStore.serviceMode == Key.modeVpn) {
            if (prepare(this) != null) {
                startActivity(Intent(this, VpnRequestActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            } else return super<LocalDnsService.Interface>.onStartCommand(intent, flags, startId)
        }
        stopRunner()
        return Service.START_NOT_STICKY
    }

    override suspend fun preInit() = DefaultNetworkListener.start(this) { underlyingNetwork = it }
    override suspend fun getActiveNetwork() = DefaultNetworkListener.get()
    override suspend fun resolver(host: String) = DnsResolverCompat.resolve(DefaultNetworkListener.get(), host)
    override suspend fun openConnection(url: URL) = DefaultNetworkListener.get().openConnection(url)

    override suspend fun startProcesses(hosts: HostsFile) {
        worker = ProtectWorker().apply { start() }
        super.startProcesses(hosts)
        val profile = data.proxy!!.profile
        if (profile.isSponsored){
            mapFd2port(startVpn())
        }else{
            sendFd(startVpn())
        }

    }

    override fun buildAdditionalArguments(cmd: ArrayList<String>): ArrayList<String> {
        cmd += "-V"
        return cmd
    }

    private suspend fun startVpn(): FileDescriptor {
        val profile = data.proxy!!.profile
        val builder = Builder()
                .setConfigureIntent(Core.configureIntent(this))
                .setSession(profile.formattedName)
                .setMtu(VPN_MTU)
                .addAddress(profile.localIP, 24)
                .addDnsServer(profile.remoteDns)

        if (profile.ipv6) builder.addAddress(PRIVATE_VLAN6_CLIENT, 126)

        if (profile.proxyApps) {
            val me = packageName
            profile.individual.split('\n')
                    .filter { it != me }
                    .forEach {
                        try {
                            if (profile.bypass) builder.addDisallowedApplication(it)
                            else builder.addAllowedApplication(it)
                        } catch (ex: PackageManager.NameNotFoundException) {
                            printLog(ex)
                        }
                    }
            if (!profile.bypass) builder.addAllowedApplication(me)
        }

        when (profile.route) {
            Acl.ALL, Acl.BYPASS_CHN, Acl.CUSTOM_RULES -> {
                builder.addRoute("0.0.0.0", 0)
                if (profile.ipv6) builder.addRoute("::", 0)
            }
            else -> {
                resources.getStringArray(R.array.bypass_private_route).forEach {
                    val subnet = Subnet.fromString(it)!!
                    builder.addRoute(subnet.address.hostAddress, subnet.prefixSize)
                }
                builder.addRoute(profile.remoteDns, 32)
                // https://issuetracker.google.com/issues/149636790
                if (profile.ipv6) builder.addRoute("2000::", 3)
            }
        }

        metered = profile.metered
        active = true   // possible race condition here?
        if (Build.VERSION.SDK_INT >= 22) {
            builder.setUnderlyingNetworks(underlyingNetworks)
            if (Build.VERSION.SDK_INT >= 29) builder.setMetered(metered)
        }

        val conn = builder.establish() ?: throw NullConnectionException()
        this.conn = conn
        if (profile.isSponsored){

            //start middleware rewriter

            val rewriterRemoteSocket = DatagramSocket(null)
            rewriterRemoteSocket.setSoTimeout(1000)
            rewriterRemoteSocket.bind(InetSocketAddress(profile.sourcePort)) // bind socatPort for public end
            val addrToSSRemote = InetSocketAddress(profile.host,profile.remotePort) // remember the profile.host
            protect(rewriterRemoteSocket)

            val rewriterLocalSocket = DatagramSocket(null)
            rewriterLocalSocket.setSoTimeout(1000)
            rewriterLocalSocket.bind(InetSocketAddress(DataStore.portLocalMiddleware)) // listen to portLocalMiddleware
            protect(rewriterLocalSocket)
            var addrToMiddleware : InetSocketAddress? = null

            middlewareSendThread = Thread(Runnable {
                try {
                    val dataBuf = ByteBuffer.allocate(VPN_MTU)// TODO: CHEKC here for MTU
                    val inPacket = DatagramPacket(dataBuf.array(), VPN_MTU)
                    while (true) {
                        var succeeded = false
                        try {
                            rewriterLocalSocket.receive(inPacket)
                            //data.proxy!!.trafficMonitor!!.current.rxTotal += packet.length
                            succeeded=true

                        }catch (e: SocketTimeoutException){

                        }
                        if (succeeded && inPacket.length > 0) {

                            val outPacket = DatagramPacket(dataBuf.array(), inPacket.length, addrToSSRemote)
                            rewriterRemoteSocket.send(outPacket)
                            if (addrToMiddleware != null) {
                            } else {
                                addrToMiddleware = InetSocketAddress(inPacket.address,inPacket.port)
                                Log.i(TAG, "middleware connected")
                            }

                            dataBuf.clear()
                        }else{
                            Thread.sleep(1)
                        }
                    }
                } catch (e: Exception) {
                    // Catch any exception
                    Log.e(TAG, "middleware send fucked up")
                    //socket.close()
                    e.printStackTrace()
                } finally {
                    rewriterRemoteSocket.close()
                    Log.i(TAG, "middleware send  closed")
                }
            }, "middlewareSendRunnable")

            //start the service
            middlewareSendThread?.start()
            Log.i(TAG, "middlewareSendRunnable start")
            middlewareRecvThread = Thread(Runnable {
                try {

                    val dataBuf = ByteBuffer.allocate(VPN_MTU)// TODO: CHEKC here for MTU
                    val inPacket = DatagramPacket(dataBuf.array(), VPN_MTU)
                    while (true) {
                        var succeeded = false
                        try {
                            rewriterRemoteSocket.receive(inPacket)
                            //data.proxy!!.trafficMonitor!!.current.rxTotal += packet.length
                            succeeded=true
                        }catch (e: SocketTimeoutException){

                        }finally {

                        }
                        if (succeeded && inPacket.length > 0) {
                            if (addrToMiddleware != null) {
                                val outPacket = DatagramPacket(dataBuf.array(), inPacket.length, addrToMiddleware)
                                rewriterLocalSocket.send(outPacket)
                            } else {
                                Log.i(TAG, "addrToMiddleware is not configured, drop packet")
                            }

                            dataBuf.clear()
                        }else{
                            Thread.sleep(1)
                        }
                    }

                } catch (e: Exception) {
                    // Catch any exception
                    Log.e(TAG, "middleware recv fucked up")
                    //socket.close()
                    e.printStackTrace()
                } finally {
                    rewriterLocalSocket.close()
                    Log.i(TAG, "middleware recv closed")
                }

            }, "middlewareRecvRunnable")
            //start the service
            middlewareRecvThread?.start()
            Log.i(TAG, "middlewareRecvRunnable start")
        }else{
            val cmd = arrayListOf(File(applicationInfo.nativeLibraryDir, Executable.TUN2SOCKS).absolutePath,
                    "--netif-ipaddr", profile.localIP,
                    "--socks-server-addr", "${profile.host}:${profile.remotePort}",
                    "--tunmtu", VPN_MTU.toString(),
                    "--sock-path", "sock_path",
                    "--dnsgw", "127.0.0.1:${DataStore.portLocalDns}",
                    "--loglevel", "warning")
            if (profile.ipv6) {
                cmd += "--netif-ip6addr"
                cmd += PRIVATE_VLAN6_ROUTER
            }
            cmd += "--enable-udprelay"
            data.processes!!.start(cmd, onRestartCallback = {
                try {
                    sendFd(conn.fileDescriptor)
                } catch (e: ErrnoException) {
                    stopRunner(false, e.message)
                }
            })
        }
        return conn.fileDescriptor
    }
    private suspend fun mapFd2port(fd:FileDescriptor){
        Log.i(TAG,"mapFd2port started")
        val addrToMiddlewareInput = InetSocketAddress(DataStore.listenAddress, DataStore.portLocalRaw)
        val socket = DatagramSocket(null)
        socket.bind(InetSocketAddress(0)) // bind to any address
        protect(socket)
        val sendThread = Thread(Runnable {
            try {
                val infile = FileInputStream(fd)
                val sendBuf = ByteBuffer.allocate(VPN_MTU)// TODO: CHECK here for MTU
                while (true) {
                    val length = infile.read(sendBuf.array())
                    data.proxy!!.trafficMonitor!!.current.txTotal += length
                    if (length > 0) {
                        sendBuf.limit(length) // fill with zero
                        val packet = DatagramPacket(sendBuf.array(), length, addrToMiddlewareInput)
                        socket.send(packet)
                        sendBuf.clear()
                    } else {
                        Thread.sleep(100)
                    }

                }

            } catch (e: Exception) {
                // Catch any exception
                Log.e(TAG, "raw send fucked up")
                //socket.close()
                e.printStackTrace()
            } finally {
                socket.close()
                Log.i(TAG, "raw send tunnel closed")
            }
        }, "sendRunnable")

        //start the service
        sendThread.start()
        Log.i(TAG, "raw send thread start")
        val recvThread = Thread(Runnable {
            try {

                val outfile = FileOutputStream(fd)
                val dataBuf = ByteBuffer.allocate(VPN_MTU)// TODO: CHEKC here for MTU
                val packet = DatagramPacket(dataBuf.array(), VPN_MTU)
                while (true) {
                    socket.receive(packet)
                    data.proxy!!.trafficMonitor!!.current.rxTotal += packet.length
                    if (packet.length > 0) {
                        outfile.write(packet.data)
                        dataBuf.clear()
                    } else {
                        Thread.sleep(100)
                    }

                }

            } catch (e: Exception) {
                // Catch any exception
                Log.e(TAG, "raw recv fucked up")
                //socket.close()
                e.printStackTrace()
            } finally {
                socket.close()
                Log.i(TAG, "raw recv tunnel closed")
            }

        }, "recvRunnable")
        //start the service
        recvThread.start()
        Log.i(TAG, "raw recv thread start")
    }

    private suspend fun sendFd(fd: FileDescriptor) {
        var tries = 0
        val path = File(Core.deviceStorage.noBackupFilesDir, "sock_path").absolutePath
        while (true) try {
            delay(50L shl tries)
            LocalSocket().use { localSocket ->
                localSocket.connect(LocalSocketAddress(path, LocalSocketAddress.Namespace.FILESYSTEM))
                localSocket.setFileDescriptorsForSend(arrayOf(fd))
                localSocket.outputStream.write(42)
            }
            return
        } catch (e: IOException) {
            if (tries > 5) throw e
            tries += 1
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        data.binder.close()
    }
}
